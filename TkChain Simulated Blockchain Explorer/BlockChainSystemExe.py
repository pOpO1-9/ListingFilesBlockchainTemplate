import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import hashlib
import time
import tkinter.messagebox as messagebox

blockchain = None  # Initialize blockchain as None

# Define a class to represent a block in the blockchain
class Block:
    def __init__(self, data, previous_hash, name):
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.name = name
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(str(self.timestamp).encode('utf-8'))
        sha.update(self.data.encode('utf-8'))
        sha.update(self.previous_hash.encode('utf-8'))
        return sha.hexdigest()

# Define a class to represent the blockchain
class Blockchain:
    user_accounts = {}

    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block("Paul's Blockchain", "0", "Genesis")

    def add_block(self, data, block_name=None):  # Add a default value for block_name
        previous_block = self.chain[-1]
        if block_name is None:
            block_name = f"Block {len(self.chain)}"
        new_block = Block(data, previous_block.hash, block_name)
        self.chain.append(new_block)

    def search(self, search_term):
        results = []
        for block in self.chain:
            if block.data == search_term or block.name == search_term:
                results.append(block)
        return results

def login_user():
    global blockchain
    global authentication_window  # Use global to indicate that authentication_window is a global variable

    username = authentication_window.entry_username_login.get()
    password = authentication_window.entry_password_login.get()

    if username in Blockchain.user_accounts:
        stored_hashed_password = Blockchain.user_accounts[username]
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if stored_hashed_password == hashed_password:
            status_label.config(text=f"User '{username}' logged in.")
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")

            # Create a blockchain instance for the logged-in user
            blockchain = Blockchain()

        else:
            status_label.config(text="Invalid username or password.")
            messagebox.showerror("Login Failed", "Invalid username or password.")
    else:
        status_label.config(text="User not found.")
        messagebox.showerror("Login Failed", "User not found.")

def register_user():
    global authentication_window  # Use global to indicate that authentication_window is a global variable

    username = authentication_window.entry_username.get()
    password = authentication_window.entry_password.get()

    if username not in Blockchain.user_accounts:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        Blockchain.user_accounts[username] = hashed_password
        status_label.config(text=f"User '{username}' registered. Please log in.")
    else:
        status_label.config(text=f"User '{username}' already exists.")

def show_authentication_page():
    global authentication_window  # Use global to indicate that authentication_window is a global variable
    authentication_window = tk.Toplevel(root)
    authentication_window.title("Authentication")

    label_username_login = ttk.Label(authentication_window, text="Username:")
    label_username_login.pack()

    authentication_window.entry_username_login = ttk.Entry(authentication_window)
    authentication_window.entry_username_login.pack()

    label_password_login = ttk.Label(authentication_window, text="Password:")
    label_password_login.pack()

    authentication_window.entry_password_login = ttk.Entry(authentication_window, show="*")
    authentication_window.entry_password_login.pack()

    login_button = ttk.Button(authentication_window, text="Login", command=login_user)
    login_button.pack()

    label_username = ttk.Label(authentication_window, text="New Username:")
    label_username.pack()

    authentication_window.entry_username = ttk.Entry(authentication_window)
    authentication_window.entry_username.pack()

    label_password = ttk.Label(authentication_window, text="New Password:")
    label_password.pack()

    authentication_window.entry_password = ttk.Entry(authentication_window, show="*")
    authentication_window.entry_password.pack()

    register_button = ttk.Button(authentication_window, text="Register", command=register_user)
    register_button.pack()

# Create the GUI
root = tk.Tk()
root.title("Blockchain")
root.geometry("800x600")  # Set window dimensions

# Custom styles for themed widgets
style = ttk.Style()
style.configure("TButton", font=("Helvetica", 12))
style.configure("TLabel", font=("Helvetica", 12))

# Show the authentication page initially
show_authentication_page()

# Function to open a file dialog and add a file to a block
def on_drop():
    file_path = filedialog.askopenfilename()
    if blockchain is not None:  # Check if blockchain is created
        block_name = entry_block_name.get()
        blockchain.add_block(file_path, block_name)
        status_label.config(text=f"File added to block '{block_name}': {file_path}")
    else:
        status_label.config(text="Create a blockchain first.")

def create_new_block():
    global blockchain  # Add this line to declare blockchain as a global variable
    block_name = entry_block_name.get()
    block_data = entry_block_data.get()

    if blockchain is not None:  # Check if blockchain is initialized
        blockchain.add_block(block_data, block_name)
        status_label.config(text=f"New block created: {block_name}")
    else:
        status_label.config(text="Blockchain not initialized. Please log in.")

# Function to search the blockchain
def search_blockchain():
    if blockchain is not None:  # Check if blockchain is created
        search_term = entry_search.get()
        results = blockchain.search(search_term)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)  # Clear previous results

        if len(results) > 0:
            for result in results:
                result_text.insert(tk.END, f"Name/ID: {result.name}\n")
                result_text.insert(tk.END, f"Data: {result.data}\n")
                result_text.insert(tk.END, f"Hash: {result.hash}\n")
                result_text.insert(tk.END, f"Timestamp: {result.timestamp}\n")
                result_text.insert(tk.END, f"Previous Hash: {result.previous_hash}\n\n")
            result_text.config(state=tk.DISABLED)
        else:
            result_text.insert(tk.END, "No results found.")
            result_text.config(state=tk.DISABLED)
    else:
        status_label.config(text="Create a blockchain first.")

# Label for block name
label_block_name = ttk.Label(root, text="Block Name/ID:")
label_block_name.place(x=20, y=20)

# Entry field for block name
entry_block_name = ttk.Entry(root)
entry_block_name.place(x=180, y=20)

# Label for adding a file
label_add_file = ttk.Label(root, text="Add File to Block:")
label_add_file.place(x=20, y=60)

# Button to add a file
add_file_button = ttk.Button(root, text="Browse", command=on_drop)
add_file_button.place(x=180, y=60)

# Label for block data (listing)
label_block_data = ttk.Label(root, text="Block Data (Listing):")
label_block_data.place(x=20, y=100)

# Entry field for block data (listing)
entry_block_data = ttk.Entry(root)
entry_block_data.place(x=180, y=100)

# Button to create a new block with a listing
create_block_button = ttk.Button(root, text="Create Block", command=create_new_block)
create_block_button.place(x=20, y=140)

# Label for search term
label_search = ttk.Label(root, text="Search Term:")
label_search.place(x=320, y=20)

# Entry field for search term
entry_search = ttk.Entry(root)
entry_search.place(x=420, y=20)

# Button to search the blockchain
search_button = ttk.Button(root, text="Search", command=search_blockchain)
search_button.place(x=560, y=20)

# Text widget to display results
result_text = tk.Text(root, height=20, width=80, bg="black", fg="light green")
result_text.place(x=20, y=180)
result_text.config(state=tk.DISABLED)

# Label for status
status_label = ttk.Label(root, text="", foreground="blue")
status_label.place(x=20, y=500)

root.mainloop()
