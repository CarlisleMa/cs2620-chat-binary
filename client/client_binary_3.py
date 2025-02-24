import socket
import struct
import json
import threading
import select
import queue
import argparse

# Queues & thread-stop flags
response_queue = queue.Queue()
stop_threads = False

# Global counters for logging the amount of data sent and received
total_bytes_sent = 0
total_bytes_received = 0

# Command Codes
COMMANDS = {
    "REGISTER": 1,
    "LOGIN": 2,
    "SEND": 3,
    "READ": 4,
    "LIST": 5,
    "EXIT": 6,
    "LIST_MESSAGES": 7,
    "DELETE": 8,
    "DELETE_ACCOUNT": 9
}


def listen_for_responses(sock):
    """
    Listens for all responses from the server and places them into a queue.
    Responses are in JSON format.
    """
    global stop_threads
    global total_bytes_received
    while not stop_threads:
        try:
            ready_to_read, _, _ = select.select([sock], [], [], 1)
            if not ready_to_read:
                continue

            # Read response header (4 bytes for payload length)
            header = sock.recv(4)
            if len(header) < 4:
                continue

            payload_len = struct.unpack("!I", header)[0]
            response_data = sock.recv(payload_len)
            if not response_data:
                continue

            chunk_size = len(response_data)
            total_bytes_received += chunk_size
            print(f"[DEBUG] Received {chunk_size} bytes (total received: {total_bytes_received} bytes)")

            response_str = response_data.decode("utf-8").strip()
            if not response_str:
                continue

            parsed_response = json.loads(response_str)
            response_queue.put(parsed_response)

        except (json.JSONDecodeError, ConnectionResetError, BrokenPipeError):
            break


def process_real_time_messages():
    """
    Continuously checks the response queue and prints real-time messages.
    """
    while not stop_threads:
        try:
            response = response_queue.get(timeout=1)
            if "type" in response and response["type"] == "message":
                print(f"\nNew message from {response['from']}: {response['message']}\n> ", end="")
            else:
                response_queue.put(response)
        except queue.Empty:
            continue


def send_request(sock, command, **kwargs):
    """
    Sends a binary request using a custom protocol:
    Header: 1 byte command code + 3 bytes payload length.
    Payload: Binary packed data (strings as length-prefixed, integers as 4 bytes).
    """
    global total_bytes_sent

    command_code = COMMANDS.get(command)
    if command_code is None:
        return {"status": "error", "message": "Invalid command"}

    # Prepare payload using a compact format (no JSON)
    payload = b""
    for key, value in kwargs.items():
        if isinstance(value, str):
            value_bytes = value.encode("utf-8")
            payload += struct.pack("!I", len(value_bytes)) + value_bytes  # String: length + bytes
        elif isinstance(value, int):
            payload += struct.pack("!I", value)  # Integer: 4 bytes
        elif isinstance(value, list):
            payload += struct.pack("!I", len(value))  # List length
            for item in value:
                item_bytes = item.encode("utf-8")
                payload += struct.pack("!I", len(item_bytes)) + item_bytes

    # Header: 1 byte command + 3 bytes payload length
    header = struct.pack("!BI", command_code, len(payload))
    sock.sendall(header + payload)

    bytes_sent = len(header) + len(payload)
    total_bytes_sent += bytes_sent
    print(f"[DEBUG] Sent {bytes_sent} bytes (total sent: {total_bytes_sent} bytes)")

    # Wait for a JSON response from the server
    try:
        response = response_queue.get(timeout=3)
        return response
    except queue.Empty:
        return {"status": "error", "message": "No response from server"}


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Client for Chat Application")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=54400, help="Server port number (default: 54400)")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    print(f"Connecting to server at {HOST}:{PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # Start the listener thread
        listener_thread = threading.Thread(target=listen_for_responses, args=(s,), daemon=True)
        listener_thread.start()

        message_processor_thread = threading.Thread(target=process_real_time_messages, daemon=True)
        message_processor_thread.start()

        # Registration / Login flow
        while True:
            action = input("Register or Login? (REGISTER/LOGIN): ").upper()
            username = input("Enter username: ")
            password = input("Enter password: ")

            response = send_request(s, action, username=username, password=password)
            print(response)

            if response["status"] == "success":
                break

        # Main command loop
        while True:
            action = input("Choose action: [SEND, READ, EXIT, LIST, DELETE, DELETE_ACCOUNT]: ").upper()

            if action == "SEND":
                recipient = input("Recipient: ")
                message = input("Message: ")
                response = send_request(s, "SEND", sender=username, recipient=recipient, message=message)
                print(response.get("message", response))

            elif action == "READ":
                limit = input("How many messages do you want to read? (default: 10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                response = send_request(s, "READ", username=username, limit=limit)
                messages = response.get("messages", [])
                if messages:
                    print("\nYour Messages:")
                    for msg in messages:
                        print(f"[{msg['timestamp']}] {msg['from']}: {msg['message']}")
                else:
                    print("No unread messages.")

            elif action == "EXIT":
                send_request(s, "EXIT", username=username)
                stop_threads = True
                break

            elif action == "LIST":
                pattern = input("Enter search pattern (leave empty for all users): ")
                response = send_request(s, "LIST", pattern=pattern)
                print(response.get("accounts", []))

            elif action == "DELETE":
                response = send_request(s, "LIST_MESSAGES", username=username)
                messages = response.get("messages", [])
                if not messages:
                    print("No messages to delete.")
                    continue

                print("\nYour Messages:")
                for msg in messages:
                    print(f"[ID: {msg['id']}] {msg['from']}: {msg['message']} (Status: {msg['status']})")

                message_ids = input("Enter message IDs to delete (comma-separated): ").strip().split(",")
                response = send_request(s, "DELETE", username=username, message_ids=message_ids)
                print(response.get("message", response))

            elif action == "DELETE_ACCOUNT":
                confirm = input("Are you sure you want to delete your account? (yes/no): ").lower()
                if confirm == "yes":
                    response = send_request(s, "DELETE_ACCOUNT", username=username)
                    print(response.get("message", response))
                    if response["status"] == "success":
                        break

            else:
                print("Unrecognized command.")

        print("\n[DEBUG] Final metrics:")
        print(f"Total bytes sent: {total_bytes_sent}")
        print(f"Total bytes received: {total_bytes_received}")
        print("Client closed.")
