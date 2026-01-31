"""
encryption module for sensitive column data
handles encryption, decryption, and key management
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()

class EncryptionManager:
    """manages encryption and decryption of sensitive data"""
    
    def __init__(self, db_manager):
        """
        initialize encryption manager
        
        args:
            db_manager: DatabaseManager instance for key storage
        """
        self.db = db_manager
        self.master_passphrase = os.getenv('MASTER_KEY_PASSPHRASE')
        
        if not self.master_passphrase:
            raise ValueError("master key passphrase not found in environment")
    
    def _derive_key_from_passphrase(self, salt):
        """derive an encryption key from the master passphrase"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_passphrase.encode()))
        return key
    
    def generate_column_key(self, table_name, column_name):
        """
        generate and store an encryption key for a specific column
        
        args:
            table_name: name of the table
            column_name: name of the column to encrypt
        
        returns:
            the generated encryption key
        """
        # generate a random encryption key for this column
        column_key = Fernet.generate_key()
        
        # encrypt the column key with master passphrase before storing
        salt = os.urandom(16)
        master_key = self._derive_key_from_passphrase(salt)
        f = Fernet(master_key)
        encrypted_column_key = f.encrypt(column_key)
        
        # store the encrypted key with its salt
        key_data = base64.b64encode(salt + encrypted_column_key).decode()
        
        # save to database
        query = """
        INSERT INTO master_keys (table_name, column_name, encrypted_key)
        VALUES (%s, %s, %s)
        ON CONFLICT (table_name, column_name) 
        DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key, created_at = CURRENT_TIMESTAMP;
        """
        self.db.execute_query(query, (table_name, column_name, key_data))
        
        return column_key
    
    def get_column_key(self, table_name, column_name):
        """
        retrieve the encryption key for a specific column
        
        args:
            table_name: name of the table
            column_name: name of the column
        
        returns:
            the decrypted column encryption key
        """
        query = """
        SELECT encrypted_key FROM master_keys
        WHERE table_name = %s AND column_name = %s;
        """
        result = self.db.execute_query(query, (table_name, column_name), fetch=True)
        
        if not result:
            raise ValueError(f"no encryption key found for {table_name}.{column_name}")
        
        # decode the stored key data
        key_data = base64.b64decode(result[0]['encrypted_key'])
        salt = key_data[:16]
        encrypted_column_key = key_data[16:]
        
        # decrypt the column key using master passphrase
        master_key = self._derive_key_from_passphrase(salt)
        f = Fernet(master_key)
        column_key = f.decrypt(encrypted_column_key)
        
        return column_key
    
    def encrypt_value(self, value, table_name, column_name):
        """
        encrypt a single value for a specific column
        
        args:
            value: plaintext value to encrypt
            table_name: table name
            column_name: column name
        
        returns:
            base64 encoded encrypted value
        """
        if value is None:
            return None
        
        # get the column's encryption key
        column_key = self.get_column_key(table_name, column_name)
        f = Fernet(column_key)
        
        # encrypt the value
        encrypted = f.encrypt(str(value).encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_value(self, encrypted_value, table_name, column_name):
        """
        decrypt a single value from a specific column
        
        args:
            encrypted_value: base64 encoded encrypted value
            table_name: table name
            column_name: column name
        
        returns:
            decrypted plaintext value
        """
        if encrypted_value is None:
            return None
        
        # get the column's encryption key
        column_key = self.get_column_key(table_name, column_name)
        f = Fernet(column_key)
        
        # decrypt the value
        encrypted = base64.b64decode(encrypted_value)
        decrypted = f.decrypt(encrypted)
        return decrypted.decode()
    
    def mask_value(self, value, mask_type='partial'):
        """
        mask sensitive data for unauthorized users
        
        args:
            value: value to mask
            mask_type: 'partial' (show last 4) or 'full' (hide all)
        
        returns:
            masked string
        """
        if value is None:
            return None
        
        value_str = str(value)
        
        if mask_type == 'full':
            return '*' * len(value_str)
        elif mask_type == 'partial':
            if len(value_str) <= 4:
                return '*' * len(value_str)
            else:
                return '*' * (len(value_str) - 4) + value_str[-4:]
        
        return value_str
    
    def is_column_encrypted(self, table_name, column_name):
        """check if a column has an encryption key"""
        query = """
        SELECT EXISTS (
            SELECT 1 FROM master_keys
            WHERE table_name = %s AND column_name = %s
        );
        """
        result = self.db.execute_query(query, (table_name, column_name), fetch=True)
        return result[0]['exists']
