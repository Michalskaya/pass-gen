import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip  # For clipboard functionality

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")
        self.master.geometry("300x350")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.pack(pady=5)

        self.length_entry = tk.Entry(master)
        self.length_entry.pack(pady=5)
        self.length_entry.insert(0, "12")  # Default length

        self.include_uppercase = tk.BooleanVar(value=True)
        self.uppercase_check = tk.Checkbutton(master, text="Include Uppercase", variable=self.include_uppercase)
        self.uppercase_check.pack(pady=2)

        self.include_lowercase = tk.BooleanVar(value=True)
        self.lowercase_check = tk.Checkbutton(master, text="Include Lowercase", variable=self.include_lowercase)
        self.lowercase_check.pack(pady=2)

        self.include_numbers = tk.BooleanVar(value=True)
        self.numbers_check = tk.Checkbutton(master, text="Include Numbers", variable=self.include_numbers)
        self.numbers_check.pack(pady=2)

        self.include_symbols = tk.BooleanVar(value=True)
        self.symbols_check = tk.Checkbutton(master, text="Include Symbols", variable=self.include_symbols)
        self.symbols_check.pack(pady=2)

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.password_display = tk.Entry(master, width=30)
        self.password_display.pack(pady=5)

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

        self.rank_label = tk.Label(master, text="Password Strength: ")
        self.rank_label.pack(pady=5)

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length <= 0:
                raise ValueError("Password length must be positive")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid positive integer for password length")
            return

        character_set = ""
        complexity = 0
        if self.include_uppercase.get():
            character_set += string.ascii_uppercase
            complexity += 1
        if self.include_lowercase.get():
            character_set += string.ascii_lowercase
            complexity += 1
        if self.include_numbers.get():
            character_set += string.digits
            complexity += 1
        if self.include_symbols.get():
            character_set += string.punctuation
            complexity += 1

        if not character_set:
            messagebox.showerror("Error", "Please select at least one character type")
            return

        password = ''.join(random.choice(character_set) for _ in range(length))
        self.password_display.delete(0, tk.END)
        self.password_display.insert(0, password)

        rank = self.rank_password(length, complexity)
        self.rank_label.config(text=f"Password Strength: {rank}")

    def rank_password(self, length, complexity):
        if length < 8:
            return "Very Weak"
        elif length < 10:
            return "Weak"
        elif length < 12:
            return "Moderate"
        elif length < 14:
            return "Strong"
        else:
            if complexity == 4:
                return "Very Strong"
            elif complexity == 3:
                return "Strong"
            else:
                return "Moderate"

    def copy_to_clipboard(self):
        password = self.password_display.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Generate a password first!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()