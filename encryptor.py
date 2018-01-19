from Crypto import Random
from Crypto.Cipher import AES
import tkinter
import tkinter.filedialog
import tkinter.messagebox
import hashlib
import os


class Encryptor():
    def __init__(self):
        self.HASH_KEY = None
        self.FILENAME = None
        self.LOCATION = os.path.dirname(__file__)
        self.BACKGROUND = "#494c52"

        self.window = tkinter.Tk()
        self.load_btn = tkinter.Button(self.window, text="Load file", command=self.load_file)
        self.encrypt_btn = tkinter.Button(self.window, text="Encrypt selected file", highlightbackground="blue",
                                          bg="blue", fg="white", command=self.tk_encrypt)
        self.decrypt_btn = tkinter.Button(self.window, text="Decrypt selected file", highlightbackground="green",
                                          bg="green", fg="white",  command=self.tk_decrypt)

        self.loaded_file_label = tkinter.Label(self.window, text="File not selected")
        self.file_label = tkinter.Label(self.window, text="File: ")
        self.key_label = tkinter.Label(self.window, text="Key: ")
        self.key_input = tkinter.Entry(self.window, bd=5, show='*')
        self.status_label = tkinter.Label(self.window, text="")

    def sha256(self, key_raw):
        hashed_key = hashlib.sha256(key_raw.encode('utf-8')).digest()
        return hashed_key

    def pad(self, raw_input):
        return raw_input + b'\0' * (AES.block_size - len(raw_input) % AES.block_size)

    def encrypt(self, input_string, key):
        input_pad = self.pad(input_string)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(input_pad)

    def decrypt(self, cipher_text, key):
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipher_text[AES.block_size:])
        return plaintext.rstrip(b'\0')

    def encrypt_file(self, filename, key):
        with open(filename, 'rb') as plain_file:
            plaintext = plain_file.read()
        file_ciphertext = self.encrypt(plaintext, key)
        filename = tkinter.filedialog.asksaveasfilename(initialdir=self.LOCATION, title="Select file",
                                                        filetypes=[("encrypted", ".enc"), ("all files", "*.*")])
        with open(filename, "wb") as encrypted_file:
            encrypted_file.write(file_ciphertext)

    def decrypt_file(self, filename, key):
        with open(filename, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()

        file_plaintext = self.decrypt(ciphertext, key)
        og_file = tkinter.filedialog.asksaveasfilename(initialdir=self.LOCATION, title="Select file",
                                                       filetypes=[("all files", "*.*")])
        with open(og_file, "wb") as plain_file:
            plain_file.write(file_plaintext)

    def load_file(self):
        self.FILENAME = tkinter.filedialog.askopenfilename(filetypes=[("Text files", "*.*")])
        self.loaded_file_label.configure(text=self.FILENAME)
        self.status_label.configure(text="")

    def tk_encrypt(self):
        try:
            raw_key = self.key_input.get()
            self.HASH_KEY = self.sha256(raw_key)
            print(self.HASH_KEY)

            if not self.HASH_KEY:
                tkinter.messagebox.showerror("Error", message="Please enter a key")
                return

            if not self.FILENAME:
                tkinter.messagebox.showerror("Error", message="No file selected for decryption")
                return

            self.encrypt_file(self.FILENAME, self.HASH_KEY)
            self.status_label.configure(text=str("File successfully encrypted"))
        except Exception as e:
            self.status_label.configure(text=str(e))

    def tk_decrypt(self):
        try:
            raw_key = self.key_input.get()

            if not raw_key:
                tkinter.messagebox.showerror("Error", message="Please enter a key")
                return

            self.HASH_KEY = self.sha256(raw_key)

            if not self.FILENAME:
                tkinter.messagebox.showerror("Error", message="No file selected for decryption")
                return

            self.decrypt_file(self.FILENAME, self.HASH_KEY)
            self.status_label.configure(text=str("File successfully decrypted"))
        except Exception as e:
            self.status_label.configure(text=str(e))

    def run(self):
        window = self.window
        window.title("File Encryptor")
        window.minsize(width=250, height=250)

        for i in range(4):
            window.rowconfigure(i, pad=10)

        window.columnconfigure(0, pad=30)
        window.columnconfigure(1, pad=30)

        self.key_label.grid(row=0, column=0)
        self.key_input.grid(row=0, column=1, sticky=tkinter.W+tkinter.E, padx=5)
        self.file_label.grid(row=1, column=0)
        self.loaded_file_label.grid(row=1, column=1, sticky=tkinter.N+tkinter.S+tkinter.W+tkinter.E)
        self.load_btn.grid(row=3, column=0, columnspan=2)
        self.status_label.grid(row=4, column=0, columnspan=2, pady=5)
        self.encrypt_btn.grid(row=5, column=0, columnspan=2, pady=5)
        self.decrypt_btn.grid(row=6, column=0, columnspan=2, pady=10)

        self.loaded_file_label["bg"] = self.BACKGROUND
        self.key_label["bg"] = self.BACKGROUND
        self.key_input["bg"] = self.BACKGROUND
        self.file_label["bg"] = self.BACKGROUND
        self.status_label["bg"] = self.BACKGROUND

        window.configure(background="#494c52")
        window.mainloop()


if __name__ == "__main__":
    app = Encryptor()
    app.run()
