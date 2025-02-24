import socket
import selectors
import sqlite3
import json
import bcrypt
import types
import struct
import argparse

# Command codes (1 byte each)
CMD_REGISTER        = 1
CMD_LOGIN           = 2
CMD_SEND            = 3
CMD_READ            = 4
CMD_EXIT            = 5
CMD_LIST_ACCOUNTS   = 6
CMD_DELETE_MESSAGES = 7
CMD_DELETE_ACCOUNT  = 8
CMD_LIST_MESSAGES   = 9

# TLV Field Types (1 byte each)
# We assume these numbers. Adjust as needed.
tlv_field_mapping = {
    11: "username",     # Used for register, login, read, delete, etc.
    12: "password",     # For register and login
    13: "sender",       # For sending messages
    14: "recipient",    # For sending messages
    15: "message",      # For sending messages
    16: "limit",        # For read messages (number of messages)
    17: "pattern",      # For list accounts (optional pattern)
    18: "message_ids"   # For delete messages (e.g., comma-separated list)
}

def parse_message(data):
    """
    Given a complete binary message, parse the header and TLV fields.
    Returns a tuple: (command, fields) where 'fields' is a dict
    with keys mapped by tlv_field_mapping.
    """
    if len(data) < 5:
        return None, {}
    # Unpack header: 1 byte command, 4 bytes payload length.
    command, payload_length = struct.unpack("!BI", data[:5])
    payload = data[5:5+payload_length]
    fields = {}
    offset = 0
    while offset < len(payload):
        # Each TLV field: 1 byte type, 2 bytes length, then value.
        if offset + 3 > len(payload):
            break  # Incomplete TLV header; exit.
        field_type, field_length = struct.unpack("!BH", payload[offset:offset+3])
        offset += 3
        if offset + field_length > len(payload):
            break  # Incomplete value; exit.
        value = payload[offset:offset+field_length].decode("utf-8")
        offset += field_length
        # Map numeric field type to a human-friendly key.
        field_name = tlv_field_mapping.get(field_type, f"field_{field_type}")
        fields[field_name] = value
    return command, fields

def reconstruct_json_request(command, fields):
    """
    Based on the command code and parsed TLV fields,
    reconstruct a JSON-like request dictionary.
    """
    if command == CMD_REGISTER:
        return {
            "command": "register",
            "username": fields.get("username"),
            "password": fields.get("password")
        }
    elif command == CMD_LOGIN:
        return {
            "command": "login",
            "username": fields.get("username"),
            "password": fields.get("password")
        }
    elif command == CMD_SEND:
        return {
            "command": "send",
            "sender": fields.get("sender"),
            "recipient": fields.get("recipient"),
            "message": fields.get("message")
        }
    elif command == CMD_READ:
        return {
            "command": "read",
            "username": fields.get("username"),
            "limit": fields.get("limit")  # number of messages to read
        }
    elif command == CMD_LIST_ACCOUNTS:
        return {
            "command": "list",
            "pattern": fields.get("pattern", "")  # empty string means list all
        }
    elif command == CMD_LIST_MESSAGES:
        return {
            "command": "list_messages",
            "username": fields.get("username")
        }
    elif command == CMD_DELETE_MESSAGES:
        return {
            "command": "delete",
            "username": fields.get("username"),
            "message_ids": fields.get("message_ids")  # e.g., "1,2,3"
        }
    elif command == CMD_DELETE_ACCOUNT:
        return {
            "command": "delete_account",
            "username": fields.get("username")
        }
    elif command == CMD_EXIT:
        return {
            "command": "exit",
            "username": fields.get("username")
        }
    else:
        # For any unknown command, just return all parsed fields.
        return {
            "command": "unknown",
            "fields": fields
        }


# Example usage:
# Suppose 'data' is a complete binary message received from a client.
# command, fields = parse_message(data)
# request_json = reconstruct_json_request(command, fields)
# print(json.dumps(request_json, indent=2))


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




# ---------------------------- Socket Server ----------------------------
def accept_wrapper(sock):
    """Accept new client connections."""
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

# Assume each client connection has a data.inb attribute (a bytes buffer)
def service_connection(key, mask):
    """
    Modified service_connection function that reads a binary message,
    parses the header and TLV fields, reconstructs a JSON request,
    and then passes it to an internal handler.
    """
    sock = key.fileobj
    data = key.data  # data should have attributes: addr and inb (a bytes buffer)

    if mask & selectors.EVENT_READ:
        try:
            recv_data = sock.recv(1024)
        except Exception as e:
            print(f"Receive error: {e}")
            recv_data = None

        if not recv_data:
            print(f"Client {data.addr} disconnected.")
            try:
                sel.unregister(sock)
            except Exception as e:
                print(f"Error unregistering socket: {e}")
            sock.close()
            return

        # Append incoming data to the buffer.
        data.inb += recv_data

        # Process complete messages (each message starts with a 5-byte header).
        while len(data.inb) >= 5:
            # Peek at header to determine full message length.
            header = data.inb[:5]
            command, payload_length = struct.unpack("!BI", header)
            total_length = 5 + payload_length
            if len(data.inb) < total_length:
                break  # Not enough data for a complete message.

            # Extract the complete message.
            message = data.inb[:total_length]
            data.inb = data.inb[total_length:]
            
            # Parse the binary message.
            cmd, fields = parse_message(message)
            
            # Reconstruct a JSON-like request (a Python dict) based on the command.
            request = reconstruct_json_request(cmd, fields)
            print("Reconstructed JSON request:", json.dumps(request))


            # Handle client request
            command = request.get("command")
            if command == "register":
                handle_register(sock, request)
            elif command == "login":
                handle_login(sock, request)
            elif command == "send":
                handle_send_message(sock, request)
            elif command == "read":
                handle_read_messages(sock, request)
            elif command == "list":
                handle_list_accounts(sock, request)
            elif command == "exit":
                handle_exit(sock, request)
            elif command == "list_messages":
                handle_list_messages(sock, request)
            elif command == "delete":
                handle_delete_messages(sock, request)
            elif command == "delete_account":
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
