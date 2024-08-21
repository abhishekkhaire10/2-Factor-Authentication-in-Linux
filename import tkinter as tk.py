import tkinter as tk
from tkinter import messagebox

def login():
    # Get username, password, current_token, and next_token from entry fields
    username = username_entry.get()
    password = password_entry.get()
    current_token = current_token_entry.get()
    next_token = next_token_entry.get()

    # Check if username, password, current_token, and next_token are correct (dummy example)
    if username == "admin" and password == "password" and current_token == "current_token" and next_token == "next_token":
        messagebox.showinfo("Login", "Login successful!")
        # Here you would proceed with whatever action you want to take after successful login
    else:
        messagebox.showerror("Login Error", "Invalid credentials")

root = tk.Tk()
root.title("Login Page")
root.configure(bg="#2c001e")  # Set background color to Ubuntu login page color

# Create a frame to contain all components
frame = tk.Frame(root, bg="#2c001e")  # Use the same background color for the frame
frame.pack(expand=True)

# Create labels and entry fields
labels = ["Username:", "Password:", "Current Token:", "Next Token:"]
entries = [tk.Entry(frame) for _ in range(len(labels))]

for i, label_text in enumerate(labels):
    label = tk.Label(frame, text=label_text, bg="#2c001e", fg="white")  # Use the same background color for the labels
    label.grid(row=i, column=0, padx=5, pady=5, sticky="e")
    entries[i].grid(row=i, column=1, padx=5, pady=5)

# Create login button
login_button = tk.Button(frame, text="Login", command=login)
login_button.grid(row=len(labels), columnspan=2, padx=5, pady=10)

# Center the frame in the window
frame.place(relx=0.5, rely=0.5, anchor="center")

root.mainloop()
