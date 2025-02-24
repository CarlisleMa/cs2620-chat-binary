import socket
import json
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import queue

class ChatClient:
    def __init__(self, root, host, port):
        self.root = root
        self.host = host
        self.port = port
        self.root.title("Chat Client")

        self.socket = None
        self.username = None

        # Thread-safe queue for server responses
        self.incoming_queue = queue.Queue()
        self.recv_buffer = ""

        self.create_login_screen()


    # ----------------------------------------------------------------------------------
    #                                 CONNECTION / I/O
    # ----------------------------------------------------------------------------------
    def connect_to_server(self):
        """Connects to the server with custom host and port."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", f"Unable to connect to {self.host}:{self.port}")
            self.root.quit()
            return

        listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        listener_thread.start()

        self.root.after(100, self.poll_incoming)


    def listen_for_messages(self):
        """
        Runs in a background thread:
        - Continuously reads data from the socket.
        - Splits the data on newline to get complete JSON strings.
        - Puts each JSON-decoded object into self.incoming_queue.
        """
        try:
            while True:
                data = self.socket.recv(4096)
                if not data:
                    break  # Socket closed
                self.recv_buffer += data.decode("utf-8")

                # The server separates JSON messages with \n
                while "\n" in self.recv_buffer:
                    line, self.recv_buffer = self.recv_buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            response = json.loads(line)
                            self.incoming_queue.put(response)
                        except json.JSONDecodeError:
                            self.update_chat("Received invalid JSON:", line)
        except OSError:
            # Socket probably closed
            pass

    def poll_incoming(self):
        """
        Called by the main (GUI) thread every 100 ms.
        - Checks the queue for new responses from the server.
        - Processes each response appropriately.
        """
        while not self.incoming_queue.empty():
            response = self.incoming_queue.get_nowait()
            self.handle_server_response(response)

        # Schedule the next poll
        self.root.after(100, self.poll_incoming)

    def handle_server_response(self, response):
        """
        Decides what to do based on whether the response is
        - a push message:  { "type": "message", "from": ..., "message": ... }
        - a command response: { "status": "success"/"error", ... }
        """
        if response.get("type") == "message":
            # This is an instant (push) message from another user
            sender = response.get("from", "Unknown")
            text = response.get("message", "")
            self.update_chat(f"{sender} -> You: {text}")
        elif "status" in response:
            # This is a normal response to some command (LOGIN, SEND, READ, etc.)
            status = response["status"]
            if status == "success":
                # Might have keys like "messages", "accounts", "message"
                self.process_success_response(response)
            else:
                # "error"
                err_msg = response.get("message", "Unknown error")
                messagebox.showerror("Error", err_msg)
        else:
            # Unknown/unexpected format
            self.update_chat("Unknown response from server:", response)

    def process_success_response(self, response):
        """
        Called if the server's response has {"status":"success", ...}.
        Display results in the chat window rather than the terminal.
        """
        # Display generic message if present
        msg = response.get("message")
        if msg:
            self.update_chat(f"[SERVER] {msg}")

        # Handle specific fields like 'messages' from READ or LIST_MESSAGES
        if "messages" in response:
            msg_list = response["messages"]
            if not msg_list:
                self.update_chat("[INFO] No messages found.")
            else:
                self.update_chat("\n--- Retrieved Messages ---")
                for msg_info in msg_list:
                    id = msg_info["id"]
                    sender = msg_info["from"]
                    text = msg_info["message"]
                    timestamp = msg_info.get("timestamp", "???")
                    status = msg_info.get("status", "")  # For LIST_MESSAGES only
                    line = f"[{timestamp}] id = [{id}]: {sender} -> {self.username}: {text} {f'({status})' if status else ''}"
                    self.update_chat(line)
                self.update_chat("--- End of List ---\n")

        # Handle 'accounts' from LIST command
        if "accounts" in response:
            accounts = response["accounts"]
            if accounts:
                self.update_chat("[INFO] Registered Users:\n" + "\n".join(accounts))
            else:
                self.update_chat("[INFO] No users found.")


        # A "delete account" or "delete messages" or other command might also have a "message" key
        # We already displayed the .get("message") above. So no further action needed
        # unless you want a more customized UI.

    # ----------------------------------------------------------------------------------
    #                                 GUI SCREENS
    # ----------------------------------------------------------------------------------
    def create_login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Register",
                  command=lambda: self.authenticate("REGISTER")).pack()
        tk.Button(self.root, text="Login",
                  command=lambda: self.authenticate("LOGIN")).pack()

    def create_chat_screen(self):
        self.clear_screen()

        # A text box for real-time chat (read-only)
        self.messages_text = tk.Text(self.root, state=tk.DISABLED, height=15)
        self.messages_text.pack()

        # An entry for sending new messages
        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack()

        # Buttons for the various functionalities
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Send Message", command=self.send_message).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Read Unread", command=self.read_messages).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="List Users", command=self.list_users).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="List All Msgs", command=self.list_all_messages).grid(row=0, column=3, padx=5)
        tk.Button(btn_frame, text="Delete Msg(s)", command=self.delete_messages).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Delete Account", command=self.delete_account).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Logout", command=self.logout).grid(row=1, column=2, padx=5, pady=5)

    # ----------------------------------------------------------------------------------
    #                              AUTH / LOGOUT
    # ----------------------------------------------------------------------------------
    def authenticate(self, command):
        """
        command can be "REGISTER" or "LOGIN".
        Connect to the server, send credentials, then move to chat screen on success.
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Username and password required.")
            return

        self.connect_to_server()  # connect once for this user
        self.username = username

        # Send the request (no immediate recv here; the background thread handles it)
        request = {
            "command": command,
            "username": username,
            "password": password
        }
        self.send_json(request)

        # Move to the chat screen now. If the server eventually says "error",
        # we'll pop an error message, but let's assume success for now:
        self.create_chat_screen()

    def logout(self):
        """
        Closes the socket, resets the GUI to login screen.
        (Optionally send an 'EXIT' command so the server knows we're offline.)
        """
        if self.socket:
            # Send an EXIT command to remove from active user list
            self.send_json({"command": "EXIT", "username": self.username})
            self.socket.close()
        self.socket = None
        self.username = None
        self.create_login_screen()

    # ----------------------------------------------------------------------------------
    #                                 COMMANDS
    # ----------------------------------------------------------------------------------
    def send_message(self):
        """Prompt for recipient, then send the message typed in the entry."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        recipient = simpledialog.askstring("Send Message", "Enter recipient username:")
        if not recipient:
            return

        message = self.message_entry.get().strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty.")
            return

        request = {
            "command": "SEND",
            "sender": self.username,
            "recipient": recipient,
            "message": message
        }
        self.send_json(request)

        # Show it in our local chat
        self.update_chat(f"You -> {recipient}: {message}")
        self.message_entry.delete(0, tk.END)

    def read_messages(self):
        """Ask the server for unread messages (e.g., limit=10 by default)."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        request = {
            "command": "READ",
            "username": self.username,
            "limit": 10
        }
        self.send_json(request)
        # The response with "messages" will come in handle_server_response.

    def list_users(self):
        """List all users (pattern matching optional)."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        pattern = simpledialog.askstring("List Users", "Enter search pattern (empty = all users):")
        pattern = pattern if pattern else ""

        request = {
            "command": "LIST",
            "pattern": pattern
        }
        self.send_json(request)

    def list_all_messages(self):
        """Ask the server for all messages, read or unread."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        request = {
            "command": "LIST_MESSAGES",
            "username": self.username
        }
        self.send_json(request)
        # The server responds with {"status":"success","messages":[...]}.

    def delete_messages(self):
        """Allows user to delete specific message IDs after listing them."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        # First, let's fetch all messages from the server so user can see the IDs
        request = {
            "command": "LIST_MESSAGES",
            "username": self.username
        }
        self.send_json(request)

        # We can't do a synchronous block here, but ideally we'd wait for the
        # messages, show them, then ask the user for the IDs. Instead, a simpler
        # approach is:
        #
        # 1) The user sees them appear in the chat area ("--- Retrieved Messages ---").
        # 2) The user runs "Delete Messages" again or we pop an askstring after a small delay.
        #
        # For demonstration, let's do a simpledialog AFTER a small .after() time:
        def ask_for_ids():
            msg_ids_str = simpledialog.askstring("Delete Messages", "Enter message IDs (comma-separated):")
            if not msg_ids_str:
                return
            ids_list = [m.strip() for m in msg_ids_str.split(",") if m.strip().isdigit()]
            if not ids_list:
                return

            delete_request = {
                "command": "DELETE",
                "username": self.username,
                "message_ids": ids_list
            }
            self.send_json(delete_request)

        # We'll give the user 1 second to see the "LIST_MESSAGES" result in the chat area
        self.root.after(1000, ask_for_ids)

    def delete_account(self):
        """Delete the currently logged-in account."""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in.")
            return

        confirm = messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?\nThis is irreversible.")
        if not confirm:
            return

        request = {
            "command": "DELETE_ACCOUNT",
            "username": self.username
        }
        self.send_json(request)
        # The server will close the connection for us, or we can do it ourselves:
        # We handle that in 'process_success_response' if we want.

    # ----------------------------------------------------------------------------------
    #                            SENDING MESSAGES (ASYNC)
    # ----------------------------------------------------------------------------------
    def send_json(self, data):
        """Send a JSON object with a newline. No blocking recv here."""
        try:
            text = json.dumps(data) + "\n"
            self.socket.sendall(text.encode("utf-8"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send data: {e}")

    # ----------------------------------------------------------------------------------
    #                           HELPER: UPDATE THE CHAT WINDOW
    # ----------------------------------------------------------------------------------
    def update_chat(self, message):
        """Inserts a new line of text into the 'messages_text' box."""
        if not hasattr(self, "messages_text"):
            return  # Might not exist if user hasn't logged in yet

        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.insert(tk.END, message + "\n")
        self.messages_text.config(state=tk.DISABLED)
        self.messages_text.see(tk.END)  # auto-scroll to bottom

    def clear_screen(self):
        """Clears all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()

    # Prompt for server address and port before launching the client
    host = simpledialog.askstring("Server Address", "Enter server IP address:", initialvalue="127.0.0.1")
    port = simpledialog.askinteger("Server Port", "Enter server port:", initialvalue=54400)

    if not host or not port:
        messagebox.showerror("Error", "Server address and port are required.")
        return

    app = ChatClient(root, host, port)
    root.mainloop()


if __name__ == "__main__":
    main()
