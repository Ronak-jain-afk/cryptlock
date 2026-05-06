import os
import unittest.mock as mock
from cryptlock.cli import encrypt_file, decrypt_file

def test_file_encryption():
    test_file = "test_file.txt"
    content = b"Hello, this is a test file for streaming encryption!" * 100
    with open(test_file, "wb") as f:
        f.write(content)
    
    # Mock getpass to return 'password123'
    # encrypt_file calls get_password(confirm=True) -> two getpass calls
    with mock.patch('cryptlock.cli.getpass', side_effect=['password123', 'password123']):
        encrypt_file(test_file)
    
    enc_file = test_file + ".enc"
    assert os.path.exists(enc_file)
    assert not os.path.exists(test_file + ".tmp") # Check no leftover tmp
    
    # Decrypt
    # decrypt_file calls get_password(confirm=False) -> one getpass call
    with mock.patch('cryptlock.cli.getpass', return_value='password123'):
        decrypt_file(enc_file, keep_encrypted=True)
    
    dec_file = test_file # It restores to the original name if we are in same dir
    with open(dec_file, "rb") as f:
        restored_content = f.read()
    
    assert restored_content == content
    print("File test passed!")
    
    # Cleanup
    os.remove(test_file)
    os.remove(enc_file)

def test_directory_encryption():
    test_dir = "test_dir"
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "file1.txt"), "w") as f:
        f.write("Content 1")
    with open(os.path.join(test_dir, "file2.txt"), "w") as f:
        f.write("Content 2")
        
    with mock.patch('cryptlock.cli.getpass', side_effect=['password123', 'password123']):
        encrypt_file(test_dir)
        
    enc_file = test_dir + ".enc"
    assert os.path.exists(enc_file)
    
    # Remove original dir
    import shutil
    shutil.rmtree(test_dir)
    
    # Decrypt
    with mock.patch('cryptlock.cli.getpass', return_value='password123'):
        decrypt_file(enc_file)
        
    assert os.path.isdir(test_dir)
    with open(os.path.join(test_dir, "file1.txt"), "r") as f:
        assert f.read() == "Content 1"
    
    print("Directory test passed!")
    
    # Cleanup
    shutil.rmtree(test_dir)

if __name__ == "__main__":
    try:
        test_file_encryption()
        test_directory_encryption()
        print("All tests passed!")
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
