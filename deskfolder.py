import tkinter as tk
from tkinter import ttk, filedialog
import os

def create_desktop_page():
    # Create main window
    root = tk.Tk()
    root.title("Ubuntu Desktop Page")
    root.geometry("600x400")

    # Create a frame to hold desktop icons
    style = ttk.Style()
    style.configure("Desktop.TFrame", background="#2c001e")  # Set background color to a shade of purple
    desktop_frame = ttk.Frame(root, padding="20", style="Desktop.TFrame")
    desktop_frame.pack(fill=tk.BOTH, expand=True)

    # Create desktop icons (buttons)
    icon1 = ttk.Button(desktop_frame, text="Open Folder", command=open_folder)
    icon1.grid(row=0, column=0, padx=10, pady=10)

    # Create a text widget to display folder contents
    global folder_contents_text
    folder_contents_text = tk.Text(desktop_frame, wrap="none", height=20, width=50)
    folder_contents_text.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

    # Add scrollbar to the text widget
    scrollbar = ttk.Scrollbar(desktop_frame, orient="vertical", command=folder_contents_text.yview)
    scrollbar.grid(row=1, column=1, sticky="ns")
    folder_contents_text.config(yscrollcommand=scrollbar.set)

    root.mainloop()

def open_folder():
    global folder_path
    folder_path = filedialog.askdirectory()  # Open file dialog to select folder
    if folder_path:  # If a folder is selected
        display_folder_contents(folder_path)

def display_folder_contents(folder_path):
    folder_contents_text.delete('1.0', tk.END)  # Clear previous contents
    folder_contents_text.insert(tk.END, "Folder contents:\n\n")
    files = os.listdir(folder_path)  # Get list of files in the folder
    for file in files:
        folder_contents_text.insert(tk.END, file + "\n")
        if file.endswith('.txt'):
            with open(os.path.join(folder_path, file), 'r') as f:
                folder_contents_text.insert(tk.END, f.read() + "\n\n")

if __name__ == "__main__":
    create_desktop_page()
