#!/usr/bin/env python3

import os
import sys
import random
import string
from PyQt5 import QtWidgets, QtGui
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as symmetric_padding

# Constants
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
CHUNK_SIZE = 64 * 1024  # 64KB

# Utility Functions

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from the password using PBKDF2."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, output_file: str, symmetric_key: bytes):
    """Encrypts the input file using AES-256 and writes the result to the output file."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)

        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            padded_data = padder.update(chunk)
            encrypted_chunk = encryptor.update(padded_data)
            f_out.write(encrypted_chunk)

        f_out.write(encryptor.update(padder.finalize()))
        f_out.write(encryptor.finalize())

def decrypt_file(input_file: str, output_file: str, symmetric_key: bytes):
    """Decrypts the input file using AES-256 and writes the result to the output file."""
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(IV_SIZE)

        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()

        with open(output_file, 'wb') as f_out:
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                decrypted_chunk = decryptor.update(chunk)
                unpadded_data = unpadder.update(decrypted_chunk)
                f_out.write(unpadded_data)

            decrypted_chunk = decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_chunk) + unpadder.finalize()
            f_out.write(unpadded_data)

def generate_random_password(length: int) -> str:
    """Generates a random password with the given length."""
    if length < 8:
        length = 8
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def generate_asymmetric_key_pair(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """Generates and saves RSA key pair to specified files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Save the private key
    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key
    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key_file, public_key_file

def load_public_key(public_key_file: str):
    """Loads a public key from a PEM file."""
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return public_key

def load_private_key(private_key_file: str):
    """Loads a private key from a PEM file."""
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return private_key

def encrypt_symmetric_key(symmetric_key: bytes, recipient_public_key_file: str, output_file: str):
    """Encrypts a symmetric key with the recipient's public key."""
    recipient_public_key = load_public_key(recipient_public_key_file)
    encrypted_key = recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, "wb") as f:
        f.write(encrypted_key)

def decrypt_symmetric_key(encrypted_key_file: str, private_key_file: str) -> bytes:
    """Decrypts a symmetric key using the recipient's private key."""
    private_key = load_private_key(private_key_file)
    with open(encrypted_key_file, "rb") as f:
        encrypted_key = f.read()
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

# PyQt5 GUI Class

class FileEncryptorApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Secure File Encryptor")
        self.setGeometry(100, 100, 700, 600)

        # Create Tabs
        self.tabs = QtWidgets.QTabWidget(self)
        self.tabs.setGeometry(10, 10, 680, 580)

        # Sender Tab
        self.sender_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.sender_tab, "Sender")

        # Receiver Tab
        self.receiver_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.receiver_tab, "Receiver")

        # Setup Sender Tab
        self.setup_sender_tab()

        # Setup Receiver Tab
        self.setup_receiver_tab()

    def setup_sender_tab(self):
        layout = QtWidgets.QVBoxLayout()

        # Section: Key Generation
        key_gen_group = QtWidgets.QGroupBox("Key Management")
        key_gen_layout = QtWidgets.QHBoxLayout()

        self.generate_keys_button = QtWidgets.QPushButton("Generate RSA Key Pair")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        key_gen_layout.addWidget(self.generate_keys_button)

        self.sender_public_key_path = QtWidgets.QLineEdit()
        self.sender_public_key_path.setPlaceholderText("Public Key Path")
        key_gen_layout.addWidget(self.sender_public_key_path)

        self.browse_sender_public_key_button = QtWidgets.QPushButton("Browse")
        self.browse_sender_public_key_button.clicked.connect(self.browse_sender_public_key)
        key_gen_layout.addWidget(self.browse_sender_public_key_button)

        key_gen_group.setLayout(key_gen_layout)
        layout.addWidget(key_gen_group)

        # Section: Import Recipient's Public Key
        recipient_key_group = QtWidgets.QGroupBox("Recipient's Public Key")
        recipient_key_layout = QtWidgets.QHBoxLayout()

        self.recipient_public_key_path = QtWidgets.QLineEdit()
        self.recipient_public_key_path.setPlaceholderText("Recipient's Public Key Path")
        recipient_key_layout.addWidget(self.recipient_public_key_path)

        self.browse_recipient_public_key_button = QtWidgets.QPushButton("Browse")
        self.browse_recipient_public_key_button.clicked.connect(self.browse_recipient_public_key)
        recipient_key_layout.addWidget(self.browse_recipient_public_key_button)

        recipient_key_group.setLayout(recipient_key_layout)
        layout.addWidget(recipient_key_group)

        # Section: Symmetric Key Generation
        sym_key_group = QtWidgets.QGroupBox("Symmetric Key")
        sym_key_layout = QtWidgets.QHBoxLayout()

        self.generate_sym_key_button = QtWidgets.QPushButton("Generate Symmetric Key")
        self.generate_sym_key_button.clicked.connect(self.generate_symmetric_key)
        sym_key_layout.addWidget(self.generate_sym_key_button)

        self.sym_key_display = QtWidgets.QLineEdit()
        self.sym_key_display.setPlaceholderText("Symmetric Key")
        self.sym_key_display.setReadOnly(True)
        sym_key_layout.addWidget(self.sym_key_display)

        sym_key_group.setLayout(sym_key_layout)
        layout.addWidget(sym_key_group)

        # Section: Encrypt Symmetric Key with Recipient's Public Key
        encrypt_key_group = QtWidgets.QGroupBox("Encrypt Symmetric Key")
        encrypt_key_layout = QtWidgets.QHBoxLayout()

        self.encrypt_key_button = QtWidgets.QPushButton("Encrypt Symmetric Key")
        self.encrypt_key_button.clicked.connect(self.encrypt_symmetric_key)
        encrypt_key_layout.addWidget(self.encrypt_key_button)

        self.encrypted_key_path = QtWidgets.QLineEdit()
        self.encrypted_key_path.setPlaceholderText("Encrypted Key Output Path")
        encrypt_key_layout.addWidget(self.encrypted_key_path)

        self.browse_encrypted_key_button = QtWidgets.QPushButton("Browse")
        self.browse_encrypted_key_button.clicked.connect(self.browse_encrypted_key_output)
        encrypt_key_layout.addWidget(self.browse_encrypted_key_button)

        encrypt_key_group.setLayout(encrypt_key_layout)
        layout.addWidget(encrypt_key_group)

        # Section: File Encryption
        file_enc_group = QtWidgets.QGroupBox("File Encryption")
        file_enc_layout = QtWidgets.QGridLayout()

        # Input File
        self.input_label = QtWidgets.QLabel("Input File:")
        self.input_path = QtWidgets.QLineEdit()
        self.browse_input_button = QtWidgets.QPushButton("Browse")
        self.browse_input_button.clicked.connect(self.browse_input_file_sender)

        file_enc_layout.addWidget(self.input_label, 0, 0)
        file_enc_layout.addWidget(self.input_path, 0, 1)
        file_enc_layout.addWidget(self.browse_input_button, 0, 2)

        # Encrypted File Output
        self.encrypted_file_label = QtWidgets.QLabel("Encrypted File Output:")
        self.encrypted_file_path = QtWidgets.QLineEdit()
        self.browse_encrypted_file_button = QtWidgets.QPushButton("Browse")
        self.browse_encrypted_file_button.clicked.connect(self.browse_encrypted_file_output)

        file_enc_layout.addWidget(self.encrypted_file_label, 1, 0)
        file_enc_layout.addWidget(self.encrypted_file_path, 1, 1)
        file_enc_layout.addWidget(self.browse_encrypted_file_button, 1, 2)

        # Encrypt Button
        self.encrypt_file_button = QtWidgets.QPushButton("Encrypt File")
        self.encrypt_file_button.clicked.connect(self.encrypt_file_sender)

        file_enc_layout.addWidget(self.encrypt_file_button, 2, 1)

        file_enc_group.setLayout(file_enc_layout)
        layout.addWidget(file_enc_group)

        # Add layout to Sender Tab
        self.sender_tab.setLayout(layout)

    def setup_receiver_tab(self):
        layout = QtWidgets.QVBoxLayout()

        # Section: Key Management
        key_gen_group = QtWidgets.QGroupBox("Key Management")
        key_gen_layout = QtWidgets.QHBoxLayout()

        self.import_private_key_button = QtWidgets.QPushButton("Import Private Key")
        self.import_private_key_button.clicked.connect(self.import_private_key)
        key_gen_layout.addWidget(self.import_private_key_button)

        self.private_key_path = QtWidgets.QLineEdit()
        self.private_key_path.setPlaceholderText("Private Key Path")
        key_gen_layout.addWidget(self.private_key_path)

        self.browse_private_key_button = QtWidgets.QPushButton("Browse")
        self.browse_private_key_button.clicked.connect(self.browse_private_key)
        key_gen_layout.addWidget(self.browse_private_key_button)

        key_gen_group.setLayout(key_gen_layout)
        layout.addWidget(key_gen_group)

        # Section: Import Encrypted Symmetric Key
        encrypted_key_group = QtWidgets.QGroupBox("Encrypted Symmetric Key")
        encrypted_key_layout = QtWidgets.QHBoxLayout()

        self.encrypted_sym_key_path = QtWidgets.QLineEdit()
        self.encrypted_sym_key_path.setPlaceholderText("Encrypted Symmetric Key Path")
        encrypted_key_layout.addWidget(self.encrypted_sym_key_path)

        self.browse_encrypted_sym_key_button = QtWidgets.QPushButton("Browse")
        self.browse_encrypted_sym_key_button.clicked.connect(self.browse_encrypted_sym_key)
        encrypted_key_layout.addWidget(self.browse_encrypted_sym_key_button)

        encrypted_key_group.setLayout(encrypted_key_layout)
        layout.addWidget(encrypted_key_group)

        # Section: Decrypt Symmetric Key
        decrypt_key_group = QtWidgets.QGroupBox("Decrypt Symmetric Key")
        decrypt_key_layout = QtWidgets.QHBoxLayout()

        self.decrypt_sym_key_button = QtWidgets.QPushButton("Decrypt Symmetric Key")
        self.decrypt_sym_key_button.clicked.connect(self.decrypt_symmetric_key)
        decrypt_key_layout.addWidget(self.decrypt_sym_key_button)

        self.decrypted_sym_key_display = QtWidgets.QLineEdit()
        self.decrypted_sym_key_display.setPlaceholderText("Decrypted Symmetric Key")
        self.decrypted_sym_key_display.setReadOnly(True)
        decrypt_key_layout.addWidget(self.decrypted_sym_key_display)

        decrypt_key_group.setLayout(decrypt_key_layout)
        layout.addWidget(decrypt_key_group)

        # Section: File Decryption
        file_dec_group = QtWidgets.QGroupBox("File Decryption")
        file_dec_layout = QtWidgets.QGridLayout()

        # Encrypted File
        self.encrypted_file_label_dec = QtWidgets.QLabel("Encrypted File:")
        self.encrypted_file_path_dec = QtWidgets.QLineEdit()
        self.browse_encrypted_file_dec_button = QtWidgets.QPushButton("Browse")
        self.browse_encrypted_file_dec_button.clicked.connect(self.browse_encrypted_file_receiver)

        file_dec_layout.addWidget(self.encrypted_file_label_dec, 0, 0)
        file_dec_layout.addWidget(self.encrypted_file_path_dec, 0, 1)
        file_dec_layout.addWidget(self.browse_encrypted_file_dec_button, 0, 2)

        # Decrypted File Output
        self.decrypted_file_label = QtWidgets.QLabel("Decrypted File Output:")
        self.decrypted_file_path = QtWidgets.QLineEdit()
        self.browse_decrypted_file_button = QtWidgets.QPushButton("Browse")
        self.browse_decrypted_file_button.clicked.connect(self.browse_decrypted_file_output)

        file_dec_layout.addWidget(self.decrypted_file_label, 1, 0)
        file_dec_layout.addWidget(self.decrypted_file_path, 1, 1)
        file_dec_layout.addWidget(self.browse_decrypted_file_button, 1, 2)

        # Decrypt Button
        self.decrypt_file_button = QtWidgets.QPushButton("Decrypt File")
        self.decrypt_file_button.clicked.connect(self.decrypt_file_receiver)

        file_dec_layout.addWidget(self.decrypt_file_button, 2, 1)

        file_dec_group.setLayout(file_dec_layout)
        layout.addWidget(file_dec_group)

        # Add layout to Receiver Tab
        self.receiver_tab.setLayout(layout)

    # Sender Tab Methods

    def generate_keys(self):
        private_key_file, public_key_file = generate_asymmetric_key_pair()
        self.sender_public_key_path.setText(os.path.abspath(public_key_file))
        QtWidgets.QMessageBox.information(self, "Keys Generated", f"RSA key pair generated.\nPublic Key: {public_key_file}\nPrivate Key: (not displayed)")

    def browse_sender_public_key(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Recipient's Public Key", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.recipient_public_key_path.setText(file_path)

    def browse_recipient_public_key(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Recipient's Public Key", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.recipient_public_key_path.setText(file_path)

    def generate_symmetric_key(self):
        sym_key = os.urandom(KEY_SIZE)
        sym_key_b64 = sym_key.hex()
        self.sym_key_display.setText(sym_key_b64)
        QtWidgets.QMessageBox.information(self, "Symmetric Key Generated", "A new symmetric key has been generated.")

    def encrypt_symmetric_key(self):
        symmetric_key_hex = self.sym_key_display.text()
        recipient_public_key_file = self.recipient_public_key_path.text()
        output_file, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Encrypted Symmetric Key", "", "Encrypted Key (*.bin);;All Files (*)")
        if not symmetric_key_hex or not recipient_public_key_file or not output_file:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please ensure that the symmetric key, recipient's public key, and output path are provided.")
            return
        try:
            symmetric_key = bytes.fromhex(symmetric_key_hex)
            encrypt_symmetric_key(symmetric_key, recipient_public_key_file, output_file)
            self.encrypted_key_path.setText(output_file)
            QtWidgets.QMessageBox.information(self, "Success", f"Symmetric key encrypted and saved to {output_file}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to encrypt symmetric key: {str(e)}")

    def browse_encrypted_key_output(self):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Encrypted Symmetric Key", "", "Encrypted Key (*.bin);;All Files (*)")
        if file_path:
            self.encrypted_key_path.setText(file_path)

    def browse_input_file_sender(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)")
        if file_path:
            self.input_path.setText(file_path)

    def browse_encrypted_file_output(self):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted Files (*.enc);;All Files (*)")
        if file_path:
            self.encrypted_file_path.setText(file_path)

    def encrypt_file_sender(self):
        input_file = self.input_path.text()
        output_file = self.encrypted_file_path.text()
        sym_key_hex = self.sym_key_display.text()

        if not input_file or not output_file or not sym_key_hex:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please ensure that the input file, output file, and symmetric key are provided.")
            return

        try:
            symmetric_key = bytes.fromhex(sym_key_hex)
            encrypt_file(input_file, output_file, symmetric_key)
            QtWidgets.QMessageBox.information(self, "Success", f"File encrypted and saved to {output_file}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to encrypt file: {str(e)}")

    # Receiver Tab Methods

    def import_private_key(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Private Key", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.private_key_path.setText(file_path)
            QtWidgets.QMessageBox.information(self, "Private Key Imported", f"Private key loaded from {file_path}.")

    def browse_private_key(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Private Key", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.private_key_path.setText(file_path)

    def browse_encrypted_sym_key(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Encrypted Symmetric Key", "", "Encrypted Key (*.bin);;All Files (*)")
        if file_path:
            self.encrypted_sym_key_path.setText(file_path)

    def decrypt_symmetric_key(self):
        encrypted_key_file = self.encrypted_sym_key_path.text()
        private_key_file = self.private_key_path.text()

        if not encrypted_key_file or not private_key_file:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please ensure that the encrypted symmetric key and private key are provided.")
            return

        try:
            symmetric_key = decrypt_symmetric_key(encrypted_key_file, private_key_file)
            symmetric_key_hex = symmetric_key.hex()
            self.decrypted_sym_key_display.setText(symmetric_key_hex)
            QtWidgets.QMessageBox.information(self, "Success", "Symmetric key decrypted successfully.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to decrypt symmetric key: {str(e)}")

    def browse_encrypted_file_receiver(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Encrypted File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)")
        if file_path:
            self.encrypted_file_path_dec.setText(file_path)

    def browse_decrypted_file_output(self):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "All Files (*)")
        if file_path:
            self.decrypted_file_path.setText(file_path)

    def decrypt_file_receiver(self):
        encrypted_file = self.encrypted_file_path_dec.text()
        output_file = self.decrypted_file_path.text()
        sym_key_hex = self.decrypted_sym_key_display.text()

        if not encrypted_file or not output_file or not sym_key_hex:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please ensure that the encrypted file, output file, and symmetric key are provided.")
            return

        try:
            symmetric_key = bytes.fromhex(sym_key_hex)
            decrypt_file(encrypted_file, output_file, symmetric_key)
            QtWidgets.QMessageBox.information(self, "Success", f"File decrypted and saved to {output_file}.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to decrypt file: {str(e)}")

# Main Execution
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = FileEncryptorApp()
    window.show()
    sys.exit(app.exec_())