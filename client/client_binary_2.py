import socket
import json
import threading
import select
import sys
import queue
import argparse
import struct


# Queues & thread-stop flags
response_queue = queue.Queue()
stop_threads = False

# Global counters for logging the amount of data sent and received
total_bytes_sent = 0
total_bytes_received = 0

def listen_for_responses(sock):
    """Continuously listens for messages from the server and stores them in a queue."""
    global total_bytes_received

    while True:
        try:
            # Read the 4-byte header: marker (1 byte), status (1 byte), payload_len (2 bytes)
            header = recv_exact(sock, 4)
            if not header:
                break

            marker, status, payload_len = struct.unpack("!BBH", header)
            if marker != 0x7E:  # 0x7E = '~'
                print("[DEBUG LISTENER] Invalid marker, skipping message")
                continue

            # Read the payload
            response_data = recv_exact(sock, payload_len)
            if response_data is None:
                break

            # Update metrics
            total_bytes_received += len(header) + len(response_data)

            # ✅ Decode payload as JSON
            response = json.loads(response_data.decode("utf-8"))
            response["status"] = "success" if status == 1 else "error"
            response_queue.put(response)  # ✅ Store response in queue

            print(f"[DEBUG LISTENER] Stored response: {response}")

        except (ConnectionResetError, BrokenPipeError):
            break


def process_real_time_messages():
    """
    Continuously checks the response queue and prints real-time messages.
    This simulates asynchronous receipt of "push" notifications from the server.
    """
    while not stop_threads:
        try:
            response = response_queue.get(timeout=1)
            # If it's a real-time message, print it immediately
            if "type" in response and response["type"] == "message":
                print(f"\nNew message from {response['from']}: {response['message']}\n> ", end="")
            else:
                # If it's not a 'message' response, put it back so the main thread can pick it up
                response_queue.put(response)
        except queue.Empty:
            continue

def recv_exact(sock, size):
    """Receive exactly 'size' bytes from the socket, logging progress."""
    data = b""
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            return None
        data += packet
    return data


def send_request(sock, request):
    """Send a request and wait for the correct response from the response queue."""
    global total_bytes_sent

    COMMAND_CODES = {
        "REGISTER": 1, "LOGIN": 2, "SEND": 3, "READ": 4,
        "LIST": 5, "EXIT": 6, "LIST_MESSAGES": 7,
        "DELETE": 8, "DELETE_ACCOUNT": 9
    }

    print(f"[DEBUG CLIENT] Preparing to send request: {request}")

    # Prepare data
    command = COMMAND_CODES.get(request.get("command", "").upper(), 0)
    username = request.get("username", "")
    password = request.get("password", "")
    recipient = request.get("recipient", "")
    message = request.get("message", "")
    limit = int(request.get("limit", 0)) if request.get("limit") else 0

    uname_bytes = username.encode("utf-8")
    pwd_bytes = password.encode("utf-8")
    rcp_bytes = recipient.encode("utf-8")
    msg_bytes = message.encode("utf-8")

    header = struct.pack(
        "!BBBBHH", command, len(uname_bytes), len(pwd_bytes),
        len(rcp_bytes), len(msg_bytes), limit
    )

    payload = uname_bytes + pwd_bytes + rcp_bytes + msg_bytes
    sock.sendall(header + payload)

    # Update metrics
    bytes_sent = len(header) + len(payload)
    total_bytes_sent += bytes_sent
    print(f"[DEBUG CLIENT] Sent {bytes_sent} bytes (total sent so far: {total_bytes_sent} bytes)")

    # ✅ Wait for the correct response from the queue
    print("[DEBUG CLIENT] Waiting for response from queue...")
    try:
        response = response_queue.get(timeout=5)  # Wait for up to 5 seconds
        print(f"[DEBUG CLIENT] Received response from queue: {response}")
        return response
    except queue.Empty:
        print("[DEBUG CLIENT] Response queue timeout")
        return {"status": "error", "message": "No response received within timeout"}



        


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Client for Chat Application")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=54400, help="Server port number (default: 54400)")
    args = parser.parse_args()

    # Assign values from arguments
    HOST = args.host
    PORT = args.port

    print(f"Connecting to server at {HOST}:{PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # Start the listener thread as soon as the client connects
        listener_thread = threading.Thread(target=listen_for_responses, args=(s,), daemon=True)
        listener_thread.start()

        # Start the real-time message processor (handles real-time message printing)
        message_processor_thread = threading.Thread(target=process_real_time_messages, daemon=True)
        message_processor_thread.start()

        # Registration / Login flow
        while True:
            action = input("Register or Login? (REGISTER/LOGIN): ").upper()
            username = input("Enter username: ")
            password = input("Enter password: ")

            response = send_request(s, {"command": action, "username": username, "password": password})
            print(response)

            if response["status"] == "success":
                print("Login successful. Listening for new messages...")
                break

        # Main command loop
        while True:
            action = input("Choose action: [SEND, READ, EXIT, LIST, DELETE, DELETE_ACCOUNT]: ").upper()

            if action == "SEND":
                recipient = input("Recipient: ")
                message = input("Message: ")
                response = send_request(s, {
                    "command": "SEND",
                    "sender": username,
                    "recipient": recipient,
                    "message": message
                })
                print(response["message"])

            elif action == "READ":
                limit = input("How many messages do you want to read? (default: 10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                response = send_request(s, {
                    "command": "READ",
                    "username": username,
                    "limit": limit
                })
                messages = response.get("messages", [])
                if messages:
                    print("\nYour Messages:")
                    for msg in messages:
                        print(f"[{msg['timestamp']}] {msg['from']}: {msg['message']}")
                else:
                    print("No unread messages.")

            elif action == "EXIT":
                print("Closing connection...")

                # Notify the server of the exit
                send_request(s, {"command": "EXIT", "username": username})

                # Stop the listener thread
                stop_threads = True

                # Join threads before closing
                listener_thread.join(timeout=2)
                message_processor_thread.join(timeout=2)

                s.close()  # Close the socket connection
                break  # Exit the client loop


            elif action == "LIST":
                pattern = input("Enter search pattern (leave empty for all users): ")
                response = send_request(s, {"command": "LIST", "pattern": pattern})
                if response["status"] == "success":
                    print("Registered Users:", response["accounts"])
                else:
                    print("Error retrieving accounts.")

            elif action == "DELETE":
                print("Listing all messages for deletion...")

                # Fetch all messages
                response = send_request(s, {"command": "LIST_MESSAGES", "username": username})
                messages = response.get("messages", [])

                if not messages:
                    print("No messages to delete.")
                    continue

                # Display messages with IDs and status
                print("\nYour Messages:")
                for msg in messages:
                    print(f"[ID: {msg['id']}] [{msg['timestamp']}] {msg['from']}: {msg['message']} (Status: {msg['status']})")

                # Ask user which messages to delete
                message_ids = input("Enter message IDs to delete (comma-separated): ").strip()
                if not message_ids:
                    print("No messages selected for deletion.")
                    continue

                message_ids_list = [msg_id.strip() for msg_id in message_ids.split(",")]
                response = send_request(s, {
                    "command": "DELETE",
                    "username": username,
                    "message_ids": message_ids_list
                })
                print(response["message"])

            elif action == "DELETE_ACCOUNT":
                confirm = input("Are you sure you want to delete your account? (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("Account deletion canceled.")
                    continue

                response = send_request(s, {"command": "DELETE_ACCOUNT", "username": username})
                print(response["message"])

                if response["status"] == "success":
                    send_request(s, {"command": "EXIT", "username": username})
                    s.close()
                    print("Client closed.")
                    break  # Exit the client

            else:
                print("Unrecognized command.")

        # Optionally, after exiting the loop, you can print final metrics
        print("\n[DEBUG] Final metrics:")
        print(f"Total bytes sent: {total_bytes_sent}")
        print(f"Total bytes received: {total_bytes_received}")
        print("Client closed.")
