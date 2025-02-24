import socket
import json
import threading
import select
import sys
import queue
import argparse


# Queues & thread-stop flags
response_queue = queue.Queue()
stop_threads = False

# Global counters for logging the amount of data sent and received
total_bytes_sent = 0
total_bytes_received = 0

def listen_for_responses(sock):
    """
    Listens for all responses from the server and places them into a queue.
    Also logs how many bytes are received for each chunk of data.
    """
    global stop_threads
    global total_bytes_received
    while not stop_threads:  # Only run if stop_threads is False
        try:
            ready_to_read, _, _ = select.select([sock], [], [], 1)
            if not ready_to_read:
                continue  # No data available, keep listening

            response_data = sock.recv(4096)
            if not response_data:
                continue  # Server closed or empty data

            # Log the number of bytes received
            chunk_size = len(response_data)
            total_bytes_received += chunk_size
            print(f"[DEBUG] Received chunk of {chunk_size} bytes (total received so far: {total_bytes_received} bytes)")

            # Decode and split by newline (each line is a JSON response)
            response_str = response_data.decode("utf-8").strip()
            if not response_str:
                continue

            responses = response_str.split("\n")
            for resp_line in responses:
                parsed_response = json.loads(resp_line)
                response_queue.put(parsed_response)  # Store all responses

        except (json.JSONDecodeError, ConnectionResetError, BrokenPipeError):
            # In real implementation, you'd handle or log the error
            break  # Exit gracefully when an error occurs


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


def send_request(sock, request):
    """
    Sends a JSON request to the server and waits for a corresponding response.
    Logs how many bytes are sent over the socket.
    """
    global total_bytes_sent

    try:
        # Convert request to JSON
        request_str = json.dumps(request) + "\n"
        request_bytes = request_str.encode("utf-8")
        sock.sendall(request_bytes)

        # Log the number of bytes sent
        bytes_sent = len(request_bytes)
        total_bytes_sent += bytes_sent
        print(f"[DEBUG] Sent {bytes_sent} bytes in JSON format (total sent so far: {total_bytes_sent} bytes)")

        # Now wait for a "command response" from the server
        while True:
            try:
                response = response_queue.get(timeout=3)  # Wait up to 3 seconds
                if "status" in response:
                    # This is likely our command response
                    return response
                elif "type" in response and response["type"] == "message":
                    # Real-time message; print it out and keep waiting
                    print(f"\nNew message from {response['from']}: {response['message']}\n> ", end="")
            except queue.Empty:
                return {"status": "error", "message": "No response received from server"}

    except (json.JSONDecodeError, ConnectionResetError, BrokenPipeError):
        return {"status": "error", "message": "Connection error or malformed response from server"}


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
