import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Program")
        
        self.msg_label = tk.Label(root, text="Message:")
        self.msg_label.pack()
        self.msg_text = tk.Text(root, height=10, width=50)
        self.msg_text.pack()
        
        self.key_label = tk.Label(root, text="Key (min 12 characters):")
        self.key_label.pack()
        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.pack()

        self.upload_btn = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack()
        
        self.cipher_var = tk.StringVar(value="vigenere")
        self.vigenere_rb = tk.Radiobutton(root, text="Vigenere", variable=self.cipher_var, value="vigenere")
        self.playfair_rb = tk.Radiobutton(root, text="Playfair", variable=self.cipher_var, value="playfair")
        self.hill_rb = tk.Radiobutton(root, text="Hill", variable=self.cipher_var, value="hill")
        self.vigenere_rb.pack()
        self.playfair_rb.pack()
        self.hill_rb.pack()
        
        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.pack()
        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.pack()
        
        self.result_label = tk.Label(root, text="Result:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=10, width=50)
        self.result_text.pack()
    
    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                content = file.read()
                self.msg_text.delete(1.0, tk.END)
                self.msg_text.insert(tk.END, content)
    
    def encrypt(self):
        msg = self.msg_text.get(1.0, tk.END).strip()
        key = self.key_entry.get().strip()
        if len(key) < 12:
            messagebox.showerror("Error", "Key must be at least 12 characters long")
            return
        
        cipher_type = self.cipher_var.get()
        if cipher_type == "vigenere":
            result = self.vigenere_encrypt(msg, key)
        elif cipher_type == "playfair":
            result = playfair_encrypt(msg, key)
        elif cipher_type == "hill":
            result = hill_encrypt(msg, key)
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)
    
    def decrypt(self):
        msg = self.msg_text.get(1.0, tk.END).strip()
        key = self.key_entry.get().strip()
        if len(key) < 12:
            messagebox.showerror("Error", "Key must be at least 12 characters long")
            return
        
        cipher_type = self.cipher_var.get()
        if cipher_type == "vigenere":
            result = self.vigenere_decrypt(msg, key)
        elif cipher_type == "playfair":
            result = playfair_decrypt(msg, key)
        elif cipher_type == "hill":
            result = hill_decrypt(msg, key)
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)
    
    def vigenere_encrypt(self, msg, key):
        key = self.extend_key(msg, key)
        encrypted = []
        for i in range(len(msg)):
            if msg[i].isalpha():
                shift = ord(key[i]) - ord('A')
                encrypted_char = chr((ord(msg[i]) - ord('A') + shift) % 26 + ord('A'))
                encrypted.append(encrypted_char)
            else:
                encrypted.append(msg[i])
        return "".join(encrypted)
    
    def vigenere_decrypt(self, msg, key):
        key = self.extend_key(msg, key)
        decrypted = []
        for i in range(len(msg)):
            if msg[i].isalpha():
                shift = ord(key[i]) - ord('A')
                decrypted_char = chr((ord(msg[i]) - ord('A') - shift + 26) % 26 + ord('A'))
                decrypted.append(decrypted_char)
            else:
                decrypted.append(msg[i])
        return "".join(decrypted)
    
    def extend_key(self, msg, key):
        key = key.upper()
        key = list(key)
        if len(msg) == len(key):
            return key
        else:
            for i in range(len(msg) - len(key)):
                key.append(key[i % len(key)])
        return "".join(key)


def generate_playfair_table(key):
    key = key.upper().replace('J', 'I')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    table = []
    for char in key:
        if char not in table and char in alphabet:
            table.append(char)
    for char in alphabet:
        if char not in table:
            table.append(char)
    return np.array(table).reshape(5, 5)

def playfair_encrypt_pair(pair, table):
    pos1 = np.where(table == pair[0])
    pos2 = np.where(table == pair[1])
    if pos1[0] == pos2[0]:  # same row
        return table[pos1[0], (pos1[1] + 1) % 5][0] + table[pos2[0], (pos2[1] + 1) % 5][0]
    elif pos1[1] == pos2[1]:  # same column
        return table[(pos1[0] + 1) % 5, pos1[1]][0] + table[(pos2[0] + 1) % 5, pos2[1]][0]
    else:  # rectangle
        return table[pos1[0], pos2[1]][0] + table[pos2[0], pos1[1]][0]

def playfair_decrypt_pair(pair, table):
    pos1 = np.where(table == pair[0])
    pos2 = np.where(table == pair[1])
    if pos1[0] == pos2[0]:  # same row
        return table[pos1[0], (pos1[1] - 1) % 5][0] + table[pos2[0], (pos2[1] - 1) % 5][0]
    elif pos1[1] == pos2[1]:  # same column
        return table[(pos1[0] - 1) % 5, pos1[1]][0] + table[(pos2[0] - 1) % 5, pos2[1]][0]
    else:  # rectangle
        return table[pos1[0], pos2[1]][0] + table[pos2[0], pos1[1]][0]

def prepare_playfair_input(msg):
    msg = msg.upper().replace('J', 'I')
    prepared_msg = []
    i = 0
    while i < len(msg):
        if i + 1 < len(msg) and msg[i] == msg[i + 1]:
            prepared_msg.append(msg[i] + 'X')
            i += 1
        elif i + 1 < len(msg):
            prepared_msg.append(msg[i] + msg[i + 1])
            i += 2
        else:
            prepared_msg.append(msg[i] + 'X')
            i += 1
    return prepared_msg

def playfair_encrypt(msg, key):
    table = generate_playfair_table(key)
    pairs = prepare_playfair_input(msg)
    encrypted = [playfair_encrypt_pair(pair, table) for pair in pairs]
    return ''.join(encrypted)

def playfair_decrypt(msg, key):
    table = generate_playfair_table(key)
    pairs = prepare_playfair_input(msg)
    decrypted = [playfair_decrypt_pair(pair, table) for pair in pairs]
    return ''.join(decrypted)


def create_key_matrix(key):
    key = key.upper().replace(' ', '')
    key_matrix = []
    key_len = len(key)
    matrix_size = int(np.sqrt(key_len))
    if matrix_size * matrix_size != key_len:
        raise ValueError("Key length must be a perfect square")
    
    k = 0
    for i in range(matrix_size):
        row = []
        for j in range(matrix_size):
            row.append(ord(key[k]) % 65)
            k += 1
        key_matrix.append(row)
    return np.array(key_matrix)

def hill_encrypt(msg, key):
    key_matrix = create_key_matrix(key)
    matrix_size = key_matrix.shape[0]
    msg = msg.upper().replace(' ', '')
    
    if len(msg) % matrix_size != 0:
        msg += 'X' * (matrix_size - len(msg) % matrix_size)
    
    msg_vector = []
    for char in msg:
        msg_vector.append(ord(char) % 65)
    
    msg_vector = np.array(msg_vector).reshape(-1, matrix_size).T
    encrypted_matrix = np.dot(key_matrix, msg_vector) % 26
    encrypted_msg = ''.join(chr(char + 65) for char in encrypted_matrix.T.flatten())
    return encrypted_msg

def hill_decrypt(msg, key):
    key_matrix = create_key_matrix(key)
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = pow(det, -1, 26)
    
    adjugate_matrix = np.linalg.inv(key_matrix) * det
    key_matrix_inv = (det_inv * adjugate_matrix) % 26
    key_matrix_inv = np.round(key_matrix_inv).astype(int) % 26
    
    msg_vector = []
    for char in msg:
        msg_vector.append(ord(char) % 65)
    
    msg_vector = np.array(msg_vector).reshape(-1, key_matrix.shape[0]).T
    decrypted_matrix = np.dot(key_matrix_inv, msg_vector) % 26
    decrypted_msg = ''.join(chr(int(char) + 65) for char in decrypted_matrix.T.flatten())
    return decrypted_msg

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
