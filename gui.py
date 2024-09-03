import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_utils import encrypt_file_inplace, decrypt_file_inplace

def select_input_file():
    file_path = filedialog.askopenfilename(title="Select Input File")
    if file_path:
        input_file_path.set(file_path)

def execute_operation():
    input_file = input_file_path.get()
    passphrase = passphrase_entry.get()

    if not input_file or not passphrase:
        messagebox.showerror("Error", "Input file and passphrase must be provided!")
        return

    try:
        if operation_var.get() == "Encrypt":
            encrypt_file_inplace(input_file, passphrase)
            messagebox.showinfo("Success", "File encrypted successfully!")
        elif operation_var.get() == "Decrypt":
            decrypt_file_inplace(input_file, passphrase)
            messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Operation failed: {str(e)}")

def update_ui():
    action_button.config(text=operation_var.get(), command=execute_operation)
    input_file_path.set("")
    passphrase_entry.delete(0, tk.END)

app = tk.Tk()
app.title("File Encryption/Decryption")
app.geometry("500x300")

input_file_path = tk.StringVar()

tk.Label(app, text="Select Operation:").pack(pady=5)
operation_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(app, text="Encrypt", variable=operation_var, value="Encrypt", command=update_ui).pack()
tk.Radiobutton(app, text="Decrypt", variable=operation_var, value="Decrypt", command=update_ui).pack()

tk.Label(app, text="Input File:").pack(pady=5)
tk.Entry(app, textvariable=input_file_path, width=50).pack()
tk.Button(app, text="Browse...", command=select_input_file).pack(pady=5)

tk.Label(app, text="Passphrase:").pack(pady=5)
passphrase_entry = tk.Entry(app, show="*", width=50)
passphrase_entry.pack()

action_button = tk.Button(app, text="Encrypt", command=execute_operation)
action_button.pack(pady=20)

update_ui()  # Initialize UI

app.mainloop()
