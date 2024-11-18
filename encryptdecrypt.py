import os
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = "C:\\Users\\yashw\\Downloads\\ISAA email\\client_secret_1051914762451-nb8moqb47kvpdbh6se3vv8el8kkm82ee.apps.googleusercontent.com.json"

class EmailEncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Email Encryption App")
        self.master.geometry("600x500")

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.encrypt_frame, text="Encrypt Email")
        self.notebook.add(self.decrypt_frame, text="Decrypt Message")

        self.initialize_encrypt_tab()

        self.initialize_decrypt_tab()

        self.file_path = None
        self.credentials = None

    def initialize_encrypt_tab(self):
        self.auth_button = tk.Button(self.encrypt_frame, text="Authorize Gmail", command=self.authorize_gmail)
        self.auth_button.pack(pady=10)

        self.label_recipient = tk.Label(self.encrypt_frame, text="Recipient Email:")
        self.label_recipient.pack()
        self.entry_recipient = tk.Entry(self.encrypt_frame, width=50)
        self.entry_recipient.pack(pady=5)

        self.label_subject = tk.Label(self.encrypt_frame, text="Subject:")
        self.label_subject.pack()
        self.entry_subject = tk.Entry(self.encrypt_frame, width=50)
        self.entry_subject.pack(pady=5)

        self.label_body = tk.Label(self.encrypt_frame, text="Email Body:")
        self.label_body.pack()
        self.text_body = tk.Text(self.encrypt_frame, height=10, width=50)
        self.text_body.pack(pady=5)

        self.label_algorithm = tk.Label(self.encrypt_frame, text="Choose Encryption Algorithm:")
        self.label_algorithm.pack()
        self.algorithm_var = tk.StringVar(self.encrypt_frame)
        self.algorithm_var.set("AES")
        self.dropdown_algorithm = tk.OptionMenu(self.encrypt_frame, self.algorithm_var, "AES", "DES", "TripleDES", "Blowfish")
        self.dropdown_algorithm.pack(pady=5)


        self.send_button = tk.Button(self.encrypt_frame, text="Send Encrypted Email", command=self.send_email)
        self.send_button.pack(pady=10)

    def initialize_decrypt_tab(self):
        self.label_encrypted = tk.Label(self.decrypt_frame, text="Encrypted Message:")
        self.label_encrypted.pack(pady=5)
        self.entry_encrypted = tk.Entry(self.decrypt_frame, width=50)
        self.entry_encrypted.pack(pady=5)

        self.label_key = tk.Label(self.decrypt_frame, text="Encryption Key (Hex):")
        self.label_key.pack(pady=5)
        self.entry_key = tk.Entry(self.decrypt_frame, width=50)
        self.entry_key.pack(pady=5)

        self.label_algorithm_decrypt = tk.Label(self.decrypt_frame, text="Choose Decryption Algorithm:")
        self.label_algorithm_decrypt.pack(pady=5)
        self.dropdown_algorithm_decrypt = tk.OptionMenu(self.decrypt_frame, self.algorithm_var, "AES", "DES", "TripleDES", "Blowfish")
        self.dropdown_algorithm_decrypt.pack(pady=5)

        self.btn_decrypt = tk.Button(self.decrypt_frame, text="Decrypt", command=self.on_decrypt)
        self.btn_decrypt.pack(pady=10)

    def authorize_gmail(self):
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        self.credentials = flow.run_local_server(port=0)
        messagebox.showinfo("Authorization", "Gmail API Authorized Successfully")

    def attach_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("Attachment", f"Attached: {os.path.basename(self.file_path)}")

    def encrypt_content(self, content, algorithm):
        if algorithm == "AES":
            key = secrets.token_bytes(32)
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "DES":
            key = secrets.token_bytes(8)
            cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "TripleDES":
            key = secrets.token_bytes(24)
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "Blowfish":
            key = secrets.token_bytes(16)
            cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
        else:
            raise ValueError("Unsupported encryption algorithm")

        encryptor = cipher.encryptor()
        padder = padding.PKCS7(cipher.algorithm.block_size).padder()
        padded_data = padder.update(content) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, key.hex()

    def send_email(self):
        if not self.credentials:
            messagebox.showwarning("Authorization Required", "Please authorize Gmail access first.")
            return

        recipient = self.entry_recipient.get()
        subject = self.entry_subject.get()
        body = self.text_body.get("1.0", tk.END)
        algorithm = self.algorithm_var.get()

        if not recipient or not subject or not body.strip():
            messagebox.showwarning("Missing Fields", "Please fill out all fields.")
            return

        encrypted_body, encryption_key = self.encrypt_content(body.encode(), algorithm)

        service = build('gmail', 'v1', credentials=self.credentials)
        message = self.create_message(recipient, subject, encrypted_body, encryption_key)

        try:
            service.users().messages().send(userId="me", body=message).execute()
            messagebox.showinfo("Email Sent", "Encrypted email sent successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {str(e)}")

    def create_message(self, to, subject, body, encryption_key):
        encoded_body = base64.urlsafe_b64encode(body).decode()
        raw_message = f"To: {to}\nSubject: {subject}\n\n{encoded_body}\nEncryption Key: {encryption_key}".encode("utf-8")
        return {'raw': base64.urlsafe_b64encode(raw_message).decode("utf-8")}
    
    def decrypt_message(self, encrypted_message, encryption_key, algorithm):

        encrypted_data = base64.urlsafe_b64decode(encrypted_message)

        key = bytes.fromhex(encryption_key)

        if algorithm == "AES":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "DES":
            cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "TripleDES":
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "Blowfish":
            cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
        else:
            raise ValueError("Unsupported decryption algorithm")

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return decrypted_data.decode("utf-8")

    def on_decrypt(self):
        encrypted_message = self.entry_encrypted.get()
        encryption_key = self.entry_key.get()
        algorithm = self.algorithm_var.get()

        try:
            decrypted_message = self.decrypt_message(encrypted_message, encryption_key, algorithm)
            messagebox.showinfo("Decrypted Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailEncryptionApp(root)
    root.mainloop()
