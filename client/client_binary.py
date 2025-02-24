import socket
import struct

HOST = "127.0.0.1"
PORT = 54401

def send_binary_message(sock, sender, recipient, message):
    sender_bytes = sender.encode("utf-8")
    recipient_bytes = recipient.encode("utf-8")
    message_bytes = message.encode("utf-8")

    header = struct.pack("!BBB", len(sender_bytes), len(recipient_bytes), len(message_bytes))
    payload = header + sender_bytes + recipient_bytes + message_bytes
    sock.sendall(payload)
    total_size = len(payload)
    print(f"Sent {total_size} bytes in binary format: {sender} -> {recipient}: {message}")

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to binary server at {HOST}:{PORT}")
        send_binary_message(s, "alice", "bob", "The quick brown fox jumps over the lazy dog.")
        send_binary_message(s, "alice", "bob", "Another message")
        print("Done sending binary messages. Closing.")
