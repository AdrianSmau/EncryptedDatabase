import os

SIMPLE_FILES_PATH = '..\\Files\\'
ENCRYPTED_FILES_PATH = '..\\Files\\Encrypted\\'


# Given the path of a (decrypted) file, returns its size, time of last access, time of last modification and time of creation
def extract_file_metadata(path):
    return os.path.getsize(path), os.path.getatime(path), os.path.getmtime(path), os.path.getctime(path)


def verify_file(file_name, is_simple):
    if not os.path.exists(SIMPLE_FILES_PATH) or not os.path.exists(ENCRYPTED_FILES_PATH):
        raise Exception("[SYSTEM] Invalid default file directories ERROR!")
    if is_simple:
        if not os.path.isfile(os.path.join(SIMPLE_FILES_PATH, file_name)):
            raise Exception("[SYSTEM] Invalid simple file path ERROR!")
    else:
        if not os.path.isfile(os.path.join(ENCRYPTED_FILES_PATH, file_name)):
            raise Exception("[SYSTEM] Invalid encrypted file path ERROR!")
