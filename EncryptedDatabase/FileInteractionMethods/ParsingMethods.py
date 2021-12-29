import os

SIMPLE_FILES_PATH = "Files/"
ENCRYPTED_FILES_PATH = "Files/Encrypted/"


class ConsoleColors:
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    METADATA = '\033[96m'
    ERROR = '\033[91m'
    ENDCHAR = '\033[0m'


# Given the path of a (decrypted) file, returns its size, time of last access, time of last modification and time of creation
def extract_file_metadata(path):
    return os.path.getsize(path), os.path.getatime(path), os.path.getmtime(path), os.path.getctime(path)


def verify_file(file_name, is_simple):
    if not os.path.exists(SIMPLE_FILES_PATH) or not os.path.exists(ENCRYPTED_FILES_PATH):
        raise Exception("[SYSTEM] Invalid default file directories ERROR!")
    if is_simple:
        if not os.path.isfile(os.path.join(SIMPLE_FILES_PATH, file_name)):
            print(f"{ConsoleColors.ERROR}[SYSTEM] Invalid simple file path ERROR!{ConsoleColors.ENDCHAR}")
            return False
    else:
        if not os.path.isfile(os.path.join(ENCRYPTED_FILES_PATH, file_name)):
            print(f"{ConsoleColors.ERROR}[SYSTEM] Invalid encrypted file path ERROR!{ConsoleColors.ENDCHAR}")
            return False
    return True
