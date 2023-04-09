import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64


class PasswordManager:
    def __init__(self, password, salt):
        """
        Initialize the PasswordManager object with a master password and a salt value.

        Args:
        - password (str): The master password used to encrypt and decrypt passwords.
        - salt (str): A randomly generated salt value used to derive a key from the master password.
        """
        password = password.encode()  # convert password to bytes
        salt = salt.encode()  # convert salt to bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )  # create a key derivation function with SHA-256 hashing algorithm
        # derive a key from the master password using PBKDF2HMAC
        key = base64.urlsafe_b64encode(kdf.derive(password))
        # initialize a Fernet object with the derived key
        self.fernet = Fernet(key)
        self.passwords = {}  # initialize an empty dictionary to store encrypted passwords

    def add_password(self, website, username, password):
        """
        Add a new password to the PasswordManager object for a given website.

        Args:
        - website (str): The name of the website for which the password is used.
        - username (str): The username or email address associated with the password.
        - password (str): The password for the website.
        """
        data = f"{username}:{password}".encode(
        )  # combine username and password into a byte string
        # encrypt the byte string using Fernet encryption
        encrypted_data = self.fernet.encrypt(data)
        # add the encrypted data to the dictionary of passwords
        self.passwords[website] = encrypted_data

    def get_password(self, website):
        """
        Retrieve the username and password for a given website from the PasswordManager object.

        Args:
        - website (str): The name of the website for which the password is used.

        Returns:
        A tuple containing the username and password for the website.
        """
        encrypted_data = self.passwords[website]  # retrieve the encrypted data for the website
        # decrypt the encrypted data using Fernet decryption
        decrypted_data = self.fernet.decrypt(encrypted_data)
        # split the decrypted byte string into username and password
        username, password = decrypted_data.decode().split(":")
        return (username, password)

# Example usage:
# salt = 'my-random-salt'  # a random salt value for key derivation
# pm = PasswordManager("my-secret-password", salt)  # initialize a PasswordManager object with a master password and a salt value
# pm.add_password("example.com", "johndoe", "password123")  # add a new password for example.com
# username, password = pm.get_password("example.com")  # retrieve the username and password for example.com
# print(f"Username: {username}")  # print the username for example.com
# print(f"Password: {password}")  # print the password for example.com
