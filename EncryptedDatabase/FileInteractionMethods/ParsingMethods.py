import os

SIMPLE_FILES_PATH = "Files/"
ENCRYPTED_FILES_PATH = "Files/Encrypted/"


class ConsoleColors:
    """
    The color codes in order to log the information in the console accordingly.
    """
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    METADATA = '\033[96m'
    ERROR = '\033[91m'
    ENDCHAR = '\033[0m'


def extract_file_metadata(path):
    """
    Given the path of a (decrypted) file, returns its size, time of last access, time of last modification and time of creation.
    :param path: Path of the decrypted file, in the Files/ folder
    :return: The file size, time of last access, time of last modification and time of creation
    """
    return os.path.getsize(path), os.path.getatime(path), os.path.getmtime(path), os.path.getctime(path)


def verify_file(file_name, is_simple):
    """
    Verifies if the folders Files/ and Files/Encrypted/ exist, and also verifies if the file whose name we received is either in the Files/ folder (if second param is True), or in Filed/Encrypted folder (otherwise)
    :param file_name: The name of the file that needs to be validated
    :param is_simple: True if we need to search in the Files/ folder, False if we need to search in the Files/Encrypted/ folder
    :return: True if everything is valid, False if the file is not found
    We raise an Exception if either the Files/, or the Files/Encrypted/ directories do not exist, which would mean a fatal error
    """
    if not os.path.exists(SIMPLE_FILES_PATH) or not os.path.exists(ENCRYPTED_FILES_PATH):
        raise Exception("[SYSTEM] Invalid default file directories ERROR!")
    if is_simple:
        if not os.path.isfile((os.path.join(SIMPLE_FILES_PATH, file_name)).replace("\\", "/")):
            print(f"{ConsoleColors.ERROR}[SYSTEM] Invalid simple file path ERROR!{ConsoleColors.ENDCHAR}")
            return False
    else:
        if not os.path.isfile((os.path.join(ENCRYPTED_FILES_PATH, file_name)).replace("\\", "/")):
            print(f"{ConsoleColors.ERROR}[SYSTEM] Invalid encrypted file path ERROR!{ConsoleColors.ENDCHAR}")
            return False
    return True
