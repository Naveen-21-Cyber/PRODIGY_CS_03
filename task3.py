import tkinter as tk
from tkinter import messagebox, filedialog
import hashlib
import requests

# Function to check if the password has been compromised
def check_password_compromised():
    password = password_entry.get()
    if password:
        try:
            # Hash the password using SHA-1
            hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
            first5_hashlib = hashed_password[:5]
            five_to_end_hashlib = hashed_password[5:]

            # Make API request using requests.Session for optimization
            with requests.Session() as session:
                url = f"https://api.pwnedpasswords.com/range/{first5_hashlib}"
                api_response = session.get(url).text.splitlines()

            # Check if the password hash exists in the API response
            for line in api_response:
                hex_d, count = line.split(":")
                if hex_d == five_to_end_hashlib:
                    messagebox.showwarning("Password Compromised", f"The password appears in {count} data breaches. Please change the '{password}' password as soon as possible.")
                    break
            else:
                messagebox.showinfo("Password is Safe", f"Congratulations! Your given password '{password}' is not compromised.")

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error fetching data: {e}")
    else:
        messagebox.showwarning("Empty Password", "Please enter a password to check.")

# Function to clear password entry and messages
def clear_entries():
    password_entry.delete(0, tk.END)
    messagebox.showinfo("Cleared", "Password field cleared and messages dismissed.")

# Setting up the GUI
root = tk.Tk()
root.title("Password Compromise Checker")
root.geometry("450x250")

# Create an input field for the password
password_label = tk.Label(root, text="Enter your Password for Compromise Check:", font=("Bahnschrift Semibold", 10))
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="", font=("Bahnschrift Semibold", 10))
password_entry.pack(pady=5)

# Create the button for checking the password compromise
check_password_button = tk.Button(root, text="Check Password Compromised", command=check_password_compromised, font=("Bahnschrift Semibold", 10))
check_password_button.pack(pady=10)

# Create a button to clear the password entry and messages
clear_button = tk.Button(root, text="Clear", command=clear_entries, font=("Bahnschrift Semibold", 10))
clear_button.pack(pady=5)

# Start the GUI loop
root.mainloop()
