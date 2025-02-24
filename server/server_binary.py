import socket
import selectors
import sqlite3
import struct
import types

sel = selectors.DefaultSelector()

conn = sqlite3.connect("chat.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        delivered INTEGER DEFAULT 0
    )
''')
conn.commit()

clients = {}

def handle_binary_message(sock):
    try:
        while True:
            header = sock.recv(3)
            if not header:
                return
            
            sender_len, recipient_len, message_len = struct.unpack("!BBB", header)
            sender_bytes = sock.recv(sender_len)
            sender = sender_bytes.decode("utf-8")
            recipient_bytes = sock.recv(recipient_len)
            recipient = recipient_bytes.decode("utf-8")
            message_bytes = sock.recv(message_len)
            message = message_bytes.decode("utf-8")
            
            total_size = 3 + sender_len + recipient_len + message_len
            print(f"Received {total_size} bytes from {sender} -> {recipient}: {message}")
            
            cursor.execute("""
                INSERT INTO messages (sender, recipient, message, delivered)
                VALUES (?, ?, ?, 0)
            """, (sender, recipient, message))
            conn.commit()
            
            if recipient in clients:
                clients[recipient].sendall(f"[{sender}] {message}".encode("utf-8"))
    except Exception as e:
        print(f"Error reading binary message: {e}")

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted binary connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1, socket.MSG_PEEK)
        if not recv_data:
            print(f"Client {data.addr} disconnected.")
            sel.unregister(sock)
            sock.close()
            return
        handle_binary_message(sock)

if __name__ == "__main__":
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 54401))
    lsock.listen()
    print("Binary Server listening on 127.0.0.1:54401")
    
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    
    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Binary server shutting down")
    finally:
        sel.close()
