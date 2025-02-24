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

# ---------------------------- Helper Functions ----------------------------
def send_response(sock, response):
    """Send a JSON response to the client."""
    try:
        response_str = json.dumps(response) + "\n"  # Ensure newline separation
        sock.sendall(response_str.encode("utf-8"))
    except BrokenPipeError:
        print("Client disconnected before response could be sent.")


def handle_register(client_socket, request):
    """Handles user registration."""
    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        send_response(client_socket, {"status": "error", "message": "Username and password required"})
        return

    # Hash password
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        send_response(client_socket, {"status": "success", "message": "Registration successful"})
    except sqlite3.IntegrityError:
        send_response(client_socket, {"status": "error", "message": "Username already exists"})

def handle_login(client_socket, request):
    """Handles user login."""
    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        send_response(client_socket, {"status": "error", "message": "Username and password required"})
        return

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result and bcrypt.checkpw(password.encode("utf-8"), result[0]):
        clients[username] = client_socket  # Store client as online

        # Check unread messages
        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND delivered = 0", (username,))
        unread_count = cursor.fetchone()[0]

        send_response(client_socket, {
            "status": "success",
            "message": "Login successful",
            "unread_messages": unread_count
        })
    else:
        send_response(client_socket, {"status": "error", "message": "Invalid username or password"})

def log_message_size(sender, recipient, message):
    """Logs the size of a sent message."""
    sender_bytes = len(sender.encode("utf-8"))
    recipient_bytes = len(recipient.encode("utf-8"))
    message_bytes = len(message.encode("utf-8"))
    
    total_size = sender_bytes + recipient_bytes + message_bytes
    print(f"Message Size: {total_size} bytes | {sender} -> {recipient}: {message}")

def handle_send_message(client_socket, request):
    """Handles sending a message, delivering instantly if the recipient is online or storing it if they are offline."""
    sender = request.get("sender")
    recipient = request.get("recipient")
    message = request.get("message")

    if not sender or not recipient or not message:
        send_response(client_socket, {"status": "error", "message": "Missing sender, recipient, or message"})
        return

    # Store the message in the database
    cursor.execute("INSERT INTO messages (sender, recipient, message, delivered) VALUES (?, ?, ?, 0)", 
                   (sender, recipient, message))
    conn.commit()

    log_message_size(sender, recipient, message)  # Log the size of the message

    # Check if the recipient is online
    if recipient in clients:
        recipient_sock = clients[recipient]
        
        # Deliver message immediately
        send_response(recipient_sock, {"type": "message", "from": sender, "message": message})

        # Mark message as delivered in the database
        cursor.execute("UPDATE messages SET delivered = 1 WHERE sender = ? AND recipient = ? AND message = ?", 
                       (sender, recipient, message))
        conn.commit()

        send_response(client_socket, {"status": "success", "message": "Message delivered instantly"})
    else:
        send_response(client_socket, {"status": "success", "message": "Message stored for offline delivery"})

def handle_read_messages(client_socket, request):
    """Retrieves undelivered messages, allowing users to specify how many they want."""
    username = request.get("username")
    limit = int(request.get("limit", 10))  # Default: 10 messages

    if not username:
        send_response(client_socket, {"status": "error", "message": "Username required"})
        return

    cursor.execute("SELECT id, sender, message, timestamp FROM messages WHERE recipient = ? AND delivered = 0 ORDER BY id ASC LIMIT ?", 
                   (username, limit))
    messages = cursor.fetchall()

    # Mark retrieved messages as delivered
    message_ids = [msg[0] for msg in messages]
    if message_ids:
        cursor.execute(f"UPDATE messages SET delivered = 1 WHERE id IN ({','.join(['?']*len(message_ids))})", message_ids)
        conn.commit()

    # Format messages to send to client
    message_list = [{"id": msg[0], "from": msg[1], "message": msg[2], "timestamp": msg[3]} for msg in messages]

    # Log message sizes
    for msg in message_list:
        log_message_size(msg["from"], username, msg["message"])

    send_response(client_socket, {"status": "success", "messages": message_list})


def handle_list_accounts(client_socket, request):
    """Handles listing accounts with optional pattern matching."""
    pattern = request.get("pattern", "%")  # Default: show all accounts
    pattern = f"%{pattern}%"  # Wildcard search

    cursor.execute("SELECT username FROM users WHERE username LIKE ?", (pattern,))
    accounts = [row[0] for row in cursor.fetchall()]

    send_response(client_socket, {"status": "success", "accounts": accounts})

def handle_exit(client_socket, request):
    """Handles client disconnection and removes them from active user list."""
    username = request.get("username")

    if username in clients:
        del clients[username]  # Remove from active users
        print(f"User {username} has disconnected.")

    # Properly unregister the socket from the selector
    try:
        sel.unregister(client_socket)
    except KeyError:
        print("Socket already unregistered.")

    send_response(client_socket, {"status": "success", "message": "User disconnected."})
    client_socket.close()  # Close the socket


def handle_list_messages(client_socket, request):
    """Retrieves all messages (read & unread) for a user."""
    username = request.get("username")

    if not username:
        send_response(client_socket, {"status": "error", "message": "Username required"})
        return

    # Retrieve all messages for the user
    cursor.execute("SELECT id, sender, message, timestamp, delivered FROM messages WHERE recipient = ? ORDER BY id ASC", 
                   (username,))
    messages = cursor.fetchall()

    # Format messages to send to client
    message_list = [
        {
            "id": msg[0], "from": msg[1], "message": msg[2], "timestamp": msg[3], "status": "Read" if msg[4] else "Unread"
        }
        for msg in messages
    ]

    send_response(client_socket, {"status": "success", "messages": message_list})

def handle_delete_messages(client_socket, request):
    """Handles deleting a specific message or multiple messages."""
    username = request.get("username")
    message_ids = request.get("message_ids")  # List of message IDs to delete

    if not username or not message_ids:
        send_response(client_socket, {"status": "error", "message": "Username and message IDs required"})
        return

    # Convert message IDs to integers (if received as strings)
    message_ids = [int(msg_id) for msg_id in message_ids]

    # Delete messages only if they belong to the user
    cursor.execute(f"DELETE FROM messages WHERE id IN ({','.join(['?']*len(message_ids))}) AND recipient = ?", 
                   message_ids + [username])
    conn.commit()

    send_response(client_socket, {"status": "success", "message": "Messages deleted successfully"})

def handle_delete_account(client_socket, request):
    """Handles account deletion, removing user data and messages."""
    username = request.get("username")

    if not username:
        send_response(client_socket, {"status": "error", "message": "Username required"})
        return

    # First, delete all messages associated with the user
    cursor.execute("DELETE FROM messages WHERE sender = ? OR recipient = ?", (username, username))

    # Then, delete the user from the database
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()

    # Remove user from active connections if they are online
    if username in clients:
        del clients[username]

    send_response(client_socket, {"status": "success", "message": "Account deleted successfully. You are now logged out."})

    # Close the connection
    client_socket.close()


def handle_binary_message(client_socket):
    """Handles messages in a custom binary format."""
    try:
        # Read fixed-size header (8 bytes: sender length, recipient length, message length)
        header = client_socket.recv(8)
        if not header:
            return

        sender_len, recipient_len, message_len = struct.unpack("!BBB", header)

        # Read sender, recipient, and message
        sender = client_socket.recv(sender_len).decode("utf-8")
        recipient = client_socket.recv(recipient_len).decode("utf-8")
        message = client_socket.recv(message_len).decode("utf-8")

        # Store message in SQLite
        cursor.execute("INSERT INTO messages (sender, recipient, message, delivered) VALUES (?, ?, ?, 0)", 
                       (sender, recipient, message))
        conn.commit()

        # If recipient is online, deliver immediately
        if recipient in clients:
            clients[recipient].sendall(f"[{sender}] {message}".encode("utf-8"))

    except Exception as e:
        print(f"Binary message error: {e}")



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
    """Handles client communication."""
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if not recv_data:
            print(f"Client {data.addr} disconnected.")
            try:
                sel.unregister(sock)  # Unregister from selector
            except KeyError:
                pass
            sock.close()
            return

        request = json.loads(recv_data.decode("utf-8"))

        # Handle client request
        command = request.get("command")
        if command == "REGISTER":
            handle_register(sock, request)
        elif command == "LOGIN":
            handle_login(sock, request)
        elif command == "SEND":
            handle_send_message(sock, request)
        elif command == "READ":
            handle_read_messages(sock, request)
        elif command == "LIST":
            handle_list_accounts(sock, request)
        elif command == "EXIT":
            handle_exit(sock, request)
        elif command == "LIST_MESSAGES":
            handle_list_messages(sock, request)
        elif command == "DELETE":
            handle_delete_messages(sock, request)
        elif command == "DELETE_ACCOUNT":
            handle_delete_account(sock, request)




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
