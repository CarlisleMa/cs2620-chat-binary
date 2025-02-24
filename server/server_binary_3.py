import socket
import selectors
import sqlite3
import json
import bcrypt
import types
import struct
import argparse

# Initialize selector for handling multiple clients
sel = selectors.DefaultSelector()

# Database connection
conn = sqlite3.connect("chat.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL
    )
''')

# Create messages table
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

# Store online clients
clients = {}

# Command Codes
COMMANDS = {
    1: "REGISTER",
    2: "LOGIN",
    3: "SEND",
    4: "READ",
    5: "LIST",
    6: "EXIT",
    7: "LIST_MESSAGES",
    8: "DELETE",
    9: "DELETE_ACCOUNT"
}


# ---------------------------- Helper Functions ----------------------------
def send_response(sock, response):
    """Send a JSON response to the client."""
    try:
        response_str = json.dumps(response) + "\n"
        response_bytes = response_str.encode("utf-8")

        # Pack response length (4 bytes)
        header = struct.pack("!I", len(response_bytes))
        sock.sendall(header + response_bytes)

    except BrokenPipeError:
        print("Client disconnected before response could be sent.")

def recv_exact(sock, length):
    """Receive an exact number of bytes from the socket."""
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by client")
            data += chunk
        except BlockingIOError:
            continue  # Keep trying until data is available
    return data


def recv_string(sock):
    """Receive a length-prefixed string from the socket."""
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    return recv_exact(sock, length).decode("utf-8")


def recv_int(sock):
    """Receive a 4-byte integer from the socket."""
    return struct.unpack("!I", recv_exact(sock, 4))[0]



# ---------------------------- Request Handlers ----------------------------
def handle_register(client_socket):
    """Handles user registration."""
    username = recv_string(client_socket)
    password = recv_string(client_socket)

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        send_response(client_socket, {"status": "success", "message": "Registration successful"})
    except sqlite3.IntegrityError:
        send_response(client_socket, {"status": "error", "message": "Username already exists"})


def handle_login(client_socket):
    """Handles user login."""
    username = recv_string(client_socket)
    password = recv_string(client_socket)

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result and bcrypt.checkpw(password.encode("utf-8"), result[0]):
        clients[username] = client_socket
        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND delivered = 0", (username,))
        unread_count = cursor.fetchone()[0]

        send_response(client_socket, {
            "status": "success",
            "message": "Login successful",
            "unread_messages": unread_count
        })
    else:
        send_response(client_socket, {"status": "error", "message": "Invalid username or password"})


def handle_send_message(client_socket):
    """Handles sending a message."""
    sender = recv_string(client_socket)
    recipient = recv_string(client_socket)
    message = recv_string(client_socket)

    cursor.execute("INSERT INTO messages (sender, recipient, message, delivered) VALUES (?, ?, ?, 0)", 
                   (sender, recipient, message))
    conn.commit()

    if recipient in clients:
        recipient_sock = clients[recipient]
        send_response(recipient_sock, {"type": "message", "from": sender, "message": message})
        cursor.execute("UPDATE messages SET delivered = 1 WHERE sender = ? AND recipient = ? AND message = ?", 
                       (sender, recipient, message))
        conn.commit()

        send_response(client_socket, {"status": "success", "message": "Message delivered instantly"})
    else:
        send_response(client_socket, {"status": "success", "message": "Message stored for offline delivery"})


def handle_read_messages(client_socket):
    """Retrieves unread messages."""
    username = recv_string(client_socket)
    limit = recv_int(client_socket)

    cursor.execute("SELECT id, sender, message, timestamp FROM messages WHERE recipient = ? AND delivered = 0 ORDER BY id ASC LIMIT ?", 
                   (username, limit))
    messages = cursor.fetchall()

    message_ids = [msg[0] for msg in messages]
    if message_ids:
        cursor.execute(f"UPDATE messages SET delivered = 1 WHERE id IN ({','.join(['?']*len(message_ids))})", message_ids)
        conn.commit()

    message_list = [{"id": msg[0], "from": msg[1], "message": msg[2], "timestamp": msg[3]} for msg in messages]
    send_response(client_socket, {"status": "success", "messages": message_list})


def handle_list_accounts(client_socket):
    """Handles listing accounts."""
    pattern = recv_string(client_socket)
    if pattern == "":
        pattern = "%"
    else:
        pattern = f"%{pattern}%"

    cursor.execute("SELECT username FROM users WHERE username LIKE ?", (pattern,))
    accounts = [row[0] for row in cursor.fetchall()]

    send_response(client_socket, {"status": "success", "accounts": accounts})


def handle_exit(client_socket):
    """Handles client disconnection."""
    username = recv_string(client_socket)
    if username in clients:
        del clients[username]
    try:
        sel.unregister(client_socket)
    except KeyError:
        pass
    send_response(client_socket, {"status": "success", "message": "User disconnected."})
    client_socket.close()


def handle_list_messages(client_socket):
    """Retrieves all messages."""
    username = recv_string(client_socket)

    cursor.execute("SELECT id, sender, message, timestamp, delivered FROM messages WHERE recipient = ? ORDER BY id ASC", 
                   (username,))
    messages = cursor.fetchall()

    message_list = [
        {"id": msg[0], "from": msg[1], "message": msg[2], "timestamp": msg[3], "status": "Read" if msg[4] else "Unread"}
        for msg in messages
    ]

    send_response(client_socket, {"status": "success", "messages": message_list})


def handle_delete_messages(client_socket):
    """Handles deleting messages."""
    username = recv_string(client_socket)
    num_ids = recv_int(client_socket)
    message_ids = [recv_string(client_socket) for _ in range(num_ids)]

    message_ids = [int(msg_id) for msg_id in message_ids]
    cursor.execute(f"DELETE FROM messages WHERE id IN ({','.join(['?']*len(message_ids))}) AND recipient = ?", 
                   message_ids + [username])
    conn.commit()

    send_response(client_socket, {"status": "success", "message": "Messages deleted successfully"})


def handle_delete_account(client_socket):
    """Handles account deletion."""
    username = recv_string(client_socket)

    cursor.execute("DELETE FROM messages WHERE sender = ? OR recipient = ?", (username, username))
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()

    if username in clients:
        del clients[username]

    send_response(client_socket, {"status": "success", "message": "Account deleted successfully."})
    client_socket.close()




# ---------------------------- Socket Server ----------------------------
def accept_wrapper(sock):
    """Accept new client connections."""
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    """Handles client communication using custom wire protocol."""
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        # Read header (4 bytes total: 1 byte command, 3 bytes payload length)
        # Read header (4 bytes total: 1 byte command, 3 bytes payload length)
        header = sock.recv(4)
        if len(header) < 4:
            return

        # Extract command and payload length correctly
        command = struct.unpack("!B", header[:1])[0]  # 1 byte (command code)
        payload_len = int.from_bytes(header[1:], byteorder="big")  # 3 bytes (payload length)


        # Read payload
        payload_data = sock.recv(payload_len)
        if len(payload_data) < payload_len:
            return

        # Map command to corresponding handler
        command_map = {
            1: handle_register,
            2: handle_login,
            3: handle_send_message,
            4: handle_read_messages,
            5: handle_list_accounts,
            6: handle_exit,
            7: handle_list_messages,
            8: handle_delete_messages,
            9: handle_delete_account
        }

        # Execute the corresponding handler
        if command in command_map:
            command_map[command](sock)


if __name__ == "__main__":
    # Parse command-line arguments for host and port
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Server IP address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=54400, help="Server port number (default: 54400)")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    # Start server with dynamic host and port
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((HOST, PORT))
    lsock.listen()
    print(f"Server listening on {HOST}:{PORT}")
    
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
        print("Server shutting down")
    finally:
        sel.close()
