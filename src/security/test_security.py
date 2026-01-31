"""test encryption functionality"""

import sys
sys.path.append('..')
from storage.database import DatabaseManager
from encryption import EncryptionManager

def test_encryption():
    print("testing encryption module...")
    
    # initialize
    db = DatabaseManager()
    crypto = EncryptionManager(db)
    
    # test key generation
    print("\ngenerating column key for employees.ssn...")
    key = crypto.generate_column_key('employees', 'ssn')
    print(f"✓ key generated: {key[:20]}...")
    
    # test encryption
    print("\ntesting encryption...")
    plaintext = "123-45-6789"
    encrypted = crypto.encrypt_value(plaintext, 'employees', 'ssn')
    print(f"plaintext: {plaintext}")
    print(f"encrypted: {encrypted[:50]}...")
    
    # test decryption
    print("\ntesting decryption...")
    decrypted = crypto.decrypt_value(encrypted, 'employees', 'ssn')
    print(f"decrypted: {decrypted}")
    
    if plaintext == decrypted:
        print("✓ encryption/decryption successful")
    else:
        print("✗ decryption failed")
    
    # test masking
    print("\ntesting data masking...")
    print(f"partial mask: {crypto.mask_value(plaintext, 'partial')}")
    print(f"full mask: {crypto.mask_value(plaintext, 'full')}")
    
    db.close()
    print("\n✓ security module test complete")

if __name__ == "__main__":
    test_encryption()
