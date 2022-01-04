import os
import shutil
import sqlite3
from datetime import datetime

from FileInteractionMethods import ParsingMethods as PM
from FileInteractionMethods.EncryptionMethods import Diffie_Hellman_Encryption as DH
from FileInteractionMethods.EncryptionMethods import RSA_Encryption as RSA

DATABASE_PATH = 'Database/files_database.db'


def initialize_database():
    """
    Initialize database in order to store the appropriate file information.
    This function deleted all the files from the Files/Encrypted folder, while also wiping the Database clean of any record.
    """
    print(f"{PM.ConsoleColors.INFO}[SYSTEM] Wiping the Encrypted folder clean...{PM.ConsoleColors.ENDCHAR}")
    for file in os.listdir(PM.ENCRYPTED_FILES_PATH):
        file_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, file)).replace("\\", "/")
        try:
            os.unlink(file_path)
        except Exception as err:
            print("Failed to delete file %s : %s" % (file_path, err))
    print(f"{PM.ConsoleColors.SUCCESS}[SYSTEM] Encrypted folder cleared...{PM.ConsoleColors.ENDCHAR}")
    print(f"{PM.ConsoleColors.INFO}[DATABASE] Database creation started...{PM.ConsoleColors.ENDCHAR}")
    init_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = init_conn.cursor()
        c.execute("""DROP TABLE IF EXISTS files""")
        c.execute("""CREATE TABLE files (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                encryption_type TEXT NOT NULL,
                encryption_param_1 INTEGER,
                encryption_param_2 INTEGER,
                encryption_param_3 INTEGER DEFAULT -1,
                encryption_param_4 INTEGER DEFAULT -1,
                size INTEGER,
                last_access TIMESTAMP,
                last_modification TIMESTAMP,
                creation_time TIMESTAMP)""")
        init_conn.commit()
        c.close()
        print(f"{PM.ConsoleColors.SUCCESS}[DATABASE] Database creation completed!{PM.ConsoleColors.ENDCHAR}")
    except sqlite3.Error as err:
        print("[DATABASE] Failed to create SqLite table", err)
    finally:
        if init_conn:
            init_conn.close()


def is_in_database(file_name):
    """
    Checks if a file with the given name already exists in the Database.
    :param file_name: The name of the file to be searched
    :return: True if any files exist, False otherwise
    """
    is_found = False
    check_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = check_conn.cursor()
        check_command = """SELECT * FROM files WHERE name = (?)"""
        c.execute(check_command, (file_name,))
        data = c.fetchall()
        if not data:
            is_found = False
        else:
            is_found = True
        c.close()
    except sqlite3.Error as err:
        print("[DATABASE] Failed to check from SqLite table", err)
    finally:
        if check_conn:
            check_conn.close()
    return is_found


def add_with_RSA(file_name):
    """
    Inserts the metadata of the specified file into the DataBase, while also encrypting the file with RSA and storing it in the Files/Encrypted folder (in encrypted form).
    :param file_name: The name of the file to be encrypted with RSA and stored in the Database
    """
    before_path = (os.path.join(PM.SIMPLE_FILES_PATH, file_name)).replace("\\", "/")
    after_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, file_name[:-4] + "_encrypted.txt")).replace("\\", "/")
    param1, param2 = RSA.compute_initial_prime_numbers()
    print(
        f"{PM.ConsoleColors.INFO}[RSA] The two selected prime numbers are: {str(param1)} and {str(param2)} {PM.ConsoleColors.ENDCHAR}")
    RSA.encrypt(before_path, after_path, param1, param2)
    size, atime, mtime, ctime = PM.extract_file_metadata(before_path)
    add_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = add_conn.cursor()
        add_command = """INSERT INTO files(name, encryption_type, encryption_param_1, encryption_param_2, size, last_access, last_modification, creation_time) VALUES (?,?,?,?,?,?,?,?)"""
        param_touple = (file_name, "RSA", param1, param2, size, atime, mtime, ctime)
        c.execute(add_command, param_touple)
        add_conn.commit()
        c.close()
        print(
            f"{PM.ConsoleColors.SUCCESS}[DATABASE] File '{file_name}' added to DataBase using RSA Encryption!{PM.ConsoleColors.ENDCHAR}")
    except sqlite3.Error as err:
        print("[DATABASE] Failed to add into SqLite table", err)
    finally:
        if add_conn:
            add_conn.close()


def add_with_DH(file_name):
    """
    Inserts the metadata of the specified file into the DataBase, while also encrypting the file with Diffie-Hellman and storing it in the Files/Encrypted folder (in encrypted form).
    :param file_name: The name of the file to be encrypted with Diffie-Hellman and stored in the Database
    """
    before_path = (os.path.join(PM.SIMPLE_FILES_PATH, file_name)).replace("\\", "/")
    after_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, file_name[:-4] + "_encrypted.txt")).replace("\\", "/")
    pb_key1, pr_key1, pb_key2, pr_key2 = DH.compute_initial_prime_numbers()

    print(
        f"{PM.ConsoleColors.INFO}[DIFFIE-HELLMAN] Party 1 has the key pair ({str(pb_key1)},{str(pr_key1)}), while Party 2 has the key pair ({str(pb_key2)},{str(pr_key2)}){PM.ConsoleColors.ENDCHAR}")

    DH.encrypt(before_path, after_path, pb_key1, pr_key1, pb_key2, pr_key2)
    size, atime, mtime, ctime = PM.extract_file_metadata(before_path)
    add_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = add_conn.cursor()
        add_command = """INSERT INTO files(name, encryption_type, encryption_param_1, encryption_param_2, encryption_param_3, encryption_param_4, size, last_access, last_modification, creation_time) VALUES (?,?,?,?,?,?,?,?,?,?)"""
        param_touple = (file_name, "DH", pb_key1, pr_key1, pb_key2, pr_key2, size, atime, mtime, ctime)
        c.execute(add_command, param_touple)
        add_conn.commit()
        c.close()
        print(
            f"{PM.ConsoleColors.SUCCESS}[DATABASE] File '{file_name}' added to DataBase using Diffie-Hellman Encryption!{PM.ConsoleColors.ENDCHAR}")
    except sqlite3.Error as err:
        print("[DATABASE] Failed to add into SqLite table", err)
    finally:
        if add_conn:
            add_conn.close()


def add_to_database(file_path, encryption_alg):
    """
    The method the user will interact with the database. Specifying the file name and the algorithm, we will encrypt the file with the chosen algorithm and add the file metadata to the Database.
    This method is secured and if something is wrong, an exception will be logged.
    Once all the validation have been made, based on the chosen Encryption Algorithm, the right method will be chosen in order to encrypt the file and store the appropriate information.
    :param file_path: In the Command Line, a dialog box will be opened so that the user can interactively select the file he wants to encrypt. Then, this function 'caches' a copy of that file in the Files/ folder,
    or does nothing, if the file is selected from the Files/ folder
    :param encryption_alg: Represents the chosen Encryption Algorithm (RSA or Diffie-Hellman) that will be used for encrypting/decrypting the file. Is RSA by default.
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print(f"{PM.ConsoleColors.ERROR}[SYSTEM] Given path is not a valid one!{PM.ConsoleColors.ENDCHAR}")
        return
    file_name = os.path.basename(file_path)
    simple_files_path = (os.path.abspath(os.path.join(PM.SIMPLE_FILES_PATH, file_name))).replace("\\", "/")
    if simple_files_path != file_path:
        if os.path.exists((os.path.join(PM.SIMPLE_FILES_PATH, file_name)).replace("\\", "/")):
            print(
                f"{PM.ConsoleColors.WARNING}[SYSTEM] A file with the name '{file_name}' already exists in the Files folder! Overriding!...{PM.ConsoleColors.ENDCHAR}")
            os.remove(simple_files_path)
        shutil.copy2(file_path, (os.path.abspath(PM.SIMPLE_FILES_PATH)).replace("\\", "/"))
        print(
            f"{PM.ConsoleColors.INFO}[SYSTEM] File '{file_name}' copied to Files folder at '{simple_files_path}'{PM.ConsoleColors.ENDCHAR}")
    else:
        print(
            f"{PM.ConsoleColors.INFO}[SYSTEM] File '{file_name}' chosen from the Files folder!{PM.ConsoleColors.ENDCHAR}")
    if is_in_database(file_name):
        print(
            f"{PM.ConsoleColors.ERROR}[DATABASE] File '{file_name}' is already in DataBase!{PM.ConsoleColors.ENDCHAR}")
        return
    if not PM.verify_file(file_name, True):
        return
    if encryption_alg == "rsa":
        add_with_RSA(file_name)
    else:
        add_with_DH(file_name)


def read_with_RSA(file_name, encrypted_file_name, param1, param2):
    """
    Decrypts a file encrypted with RSA and opens the decrypted file, after overriding the original file in the Files/ folder
    :param file_name: The name of the original file
    :param encrypted_file_name: The name of the encrypted file (that is the original name, with an appended _encrypted at the end) - example => test.txt, test_encrypted.txt
    :param param1: The first prime number needed to compute the RSA algorithm decryption
    :param param2: The second prime number needed to compute the RSA algorithm decryption
    Starts the file from the Files/ folder, after overwriting it with the decrypted version (that should be identical)
    """
    before_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, encrypted_file_name)).replace("\\", "/")
    after_path = (os.path.join(PM.SIMPLE_FILES_PATH, file_name)).replace("\\", "/")
    RSA.decrypt(before_path, after_path, param1, param2)
    os.startfile((os.path.abspath(after_path)).replace("\\", "/"))


def read_with_DH(file_name, encrypted_file_name, param1, param2, param3, param4):
    """
    Decrypts a file encrypted with Diffie-Hellman and opens the decrypted file, after overriding the original file in the Files/ folder
    :param file_name: The name of the original file
    :param encrypted_file_name: The name of the encrypted file (that is the original name, with an appended _encrypted at the end) - example => test.txt, test_encrypted.txt
    :param param1: The first prime number needed to compute the Diffie-Hellman algorithm decryption
    :param param2: The second prime number needed to compute the Diffie-Hellman algorithm decryption
    :param param3: The third prime number needed to compute the Diffie-Hellman algorithm decryption
    :param param4: The fourth prime number needed to compute the Diffie-Hellman algorithm decryption
    Starts the file from the Files/ folder, after overwriting it with the decrypted version (that should be identical)
    """
    before_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, encrypted_file_name)).replace("\\", "/")
    after_path = (os.path.join(PM.SIMPLE_FILES_PATH, file_name)).replace("\\", "/")
    DH.decrypt(before_path, after_path, param1, param2, param3, param4)
    os.startfile((os.path.abspath(after_path)).replace("\\", "/"))


# The method the users will interact with the DataBase. Being a secured method, it will log an Exception if something is wrong. We receive the original file name, and we fetch
# the metadata from the database, display it, decrypt the file, store it in the appropriate folder and open the file
def read_from_database(file_name):
    """
    The method the users will interact with the DataBase. Being a secured method, it will log an Exception if something is wrong.
    We receive the original file name, and we fetch the metadata from the database, display it, decrypt the file, store it in the Files/ folder (thus overwriting the original file, which should be identical) and open the file
    :param file_name: The name of the file that the user wants to read
    Based on the encryption method used for the chosen file, we call the appropriate method from the two above.
    """
    if not is_in_database(file_name):
        print(
            f"{PM.ConsoleColors.ERROR}[DATABASE] Error when attempting to read : File '{file_name}' is not in DataBase!{PM.ConsoleColors.ENDCHAR}")
        return
    if not PM.verify_file(file_name, True):
        return
    encrypted_file_name = file_name[:-4] + "_encrypted.txt"
    if not PM.verify_file(encrypted_file_name, False):
        return
    encryption_algorithm = ""
    metadata = ()
    rsa_params = ()
    dh_params = ()
    check_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = check_conn.cursor()
        check_command = """SELECT * FROM files WHERE name = (?)"""
        c.execute(check_command, (file_name,))
        data = c.fetchone()
        encryption_algorithm = data[2]
        rsa_params = (data[3], data[4])
        dh_params = (data[3], data[4], data[5], data[6])
        metadata = (data[1], data[7], data[8], data[9], data[10])
        c.close()
    except sqlite3.Error as err:
        print("[DATABASE] Failed to read from SqLite table", err)
    finally:
        if check_conn:
            check_conn.close()
        print(
            f"{PM.ConsoleColors.METADATA}[SYSTEM] File Metadata:\nName: {metadata[0]}\nSize: {str(metadata[1])} byte(s)\nLast access at: {datetime.fromtimestamp(metadata[2]).strftime('%d-%m-%Y')}\nLast modification at: {datetime.fromtimestamp(metadata[3]).strftime('%d-%m-%Y')}\nCreated at: {datetime.fromtimestamp(metadata[4]).strftime('%d-%m-%Y')}{PM.ConsoleColors.ENDCHAR}")
        if encryption_algorithm == "RSA":
            read_with_RSA(file_name, encrypted_file_name, rsa_params[0], rsa_params[1])
        elif encryption_algorithm == "DH":
            read_with_DH(file_name, encrypted_file_name, dh_params[0], dh_params[1], dh_params[2], dh_params[3])
        else:
            print(
                f"{PM.ConsoleColors.ERROR}[SYSTEM] Error when trying to read file - Invalid encryption algorithm!{PM.ConsoleColors.ENDCHAR}")
            return


def delete_from_database(file_name):
    """
    The method the users will interact with the DataBase. Being a secured method, it will log an Exception if something is wrong.
    Deletes file from Database, as well as its encrypted version from the Files/Encrypted folder. That means the 'cached', decrypted version remains in the Files/ folder, in case it is needed.
    :param file_name: The name of the file that the user wants to delete
    """
    if not is_in_database(file_name):
        print(
            f"{PM.ConsoleColors.ERROR}[SYSTEM] Error when attempting to delete :  File '{file_name}' is not in DataBase!{PM.ConsoleColors.ENDCHAR}")
        return
    if not PM.verify_file(file_name, True):
        return
    encrypted_file_name = file_name[:-4] + "_encrypted.txt"
    if not PM.verify_file(encrypted_file_name, False):
        return
    delete_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = delete_conn.cursor()
        delete_command = """DELETE FROM files WHERE name = (?)"""
        c.execute(delete_command, (file_name,))
        delete_conn.commit()
        c.close()
    except sqlite3.Error as err:
        print("[DATABASE] Failed to delete from SqLite table", err)
    finally:
        if delete_conn:
            delete_conn.close()
        print(
            f"{PM.ConsoleColors.SUCCESS}[DATABASE] Deleted file '{file_name}' from Database!{PM.ConsoleColors.ENDCHAR}")
        encrypted_path = (os.path.join(PM.ENCRYPTED_FILES_PATH, encrypted_file_name)).replace("\\", "/")
        os.remove(encrypted_path)
        print(
            f"{PM.ConsoleColors.SUCCESS}[SYSTEM] Removed file from encrypted files folder at {encrypted_path}{PM.ConsoleColors.ENDCHAR}")
