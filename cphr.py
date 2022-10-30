import tkinter as tk
from tkinter import ttk
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

def destroy_w():
    global output
    output.destroy()

def output_create(txt):
    global output
    output = tk.Text(window, height=16, borderwidth=0)
    output.insert(1.0, txt)
    output.configure(state="disabled")
    output.configure(inactiveselectbackground=output.cget("selectbackground"))
    output.pack()

def display ():
    global key
    global entry
    global output
    try:
        destroy_w()
    except:
        pass
    string= entry.get("1.0",tk.END)
    key_string= key.get("1.0",tk.END)
    key_string=key_string.strip()
    aes = AESCipher(key_string)
    enc = aes.encrypt(string)
    output_create(enc)

def Decrypt_message():
    global key
    global entry
    global output
    try:
        destroy_w()
    except:
        pass
    message_string= entry.get("1.0",tk.END)
    message_string=message_string.strip()
    key_string= key.get("1.0",tk.END)
    key_string=key_string.strip()
    aes = AESCipher(key_string)
    dec = aes.decrypt(message_string)
    output_create(dec)
    

if __name__=="__main__":
    option = input("Console or GUI?(c/g)\n> ")
    if option == "g" or option == "G":
        window = tk.Tk()
        window.title('Cipher Tool')
        window.minsize(width=350, height=350)
        lbl= tk.ttk.Label(text="message:")
        lbl.pack()
        entry = tk.Text(height=5, width=50)
        entry.pack(padx=1, pady=1)
        lbl2= tk.ttk.Label(text="key:")
        lbl2.pack()
        key = tk.Text(height=5, width=5)
        key.pack()
        Cphr_button = tk.ttk.Button(window,text='Cipher',command=display)
        Cphr_button.pack(padx=0.9, pady=1.6)
        Decrypt_button = tk.ttk.Button(window,text='Decrypt',command=Decrypt_message)
        Decrypt_button.pack(padx=0.9, pady=1.6)
        window.mainloop()
    elif option == "c" or option == "C":
        while True:
            i = input("1.En\n2.De\n>")
            key=input("key:\n>")
            tx = input("text:\n>")
            aes = AESCipher(key)
            if i=="1":
                enc = aes.encrypt(tx)
                print("Encrypted: ",enc)
            elif i =="2":
                dec = aes.decrypt(tx)
                print("Decrypted:",dec)
