import os
import sqlite3
import time
from datetime import datetime

from FileInteractionMethods import ParsingMethods as PM
from FileInteractionMethods.EncryptionMethods import Diffie_Hellman_Encryption as DH
from FileInteractionMethods.EncryptionMethods import RSA_Encryption as RSA

DATABASE_PATH = 'files_database.db'


# Initialize database in order to store the appropriate file information
def initialize_database():
    print("[SYSTEM] Database creation started...")
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
        init_conn.close()
        print("[SYSTEM] Database creation completed!")
    except sqlite3.Error as err:
        print("[SYSTEM] Failed to create SqLite table", err)
    finally:
        if init_conn:
            init_conn.close()


# Checks if a file is in the DataBase. Returns True if it is, False otherwise
def is_in_database(file_name):
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
        print("[SYSTEM] Failed to check from SqLite table", err)
    finally:
        if check_conn:
            check_conn.close()
    return is_found


# Inserting the metadata of the specified file into the DataBase, while also encrypting the file with RSA and storing it in the appropriate folder
def add_with_RSA(file_name):
    before_path = os.path.join(PM.SIMPLE_FILES_PATH, file_name)
    after_path = os.path.join(PM.ENCRYPTED_FILES_PATH, file_name[:-4] + "_encrypted.txt")
    param1, param2 = RSA.compute_initial_prime_numbers()
    print("[RSA] The two selected prime numbers are: " + str(param1) + " and " + str(param2))
    RSA.encrypt(before_path, after_path, param1, param2)
    size, atime, mtime, ctime = PM.extract_file_metadata(before_path)
    add_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = add_conn.cursor()
        add_command = """INSERT INTO files(name, encryption_type, encryption_param_1, encryption_param_2, size, last_access, last_modification, creation_time) VALUES (?,?,?,?,?,?,?,?)"""
        param_touple = (file_name, "RSA", param1, param2, size, atime, mtime, ctime)
        c.execute(add_command, param_touple)
        add_conn.commit()
        print("[SYSTEM] File " + file_name + " added to DataBase using RSA Encryption!")
        c.close()
    except sqlite3.Error as err:
        print("[SYSTEM] Failed to add into SqLite table", err)
    finally:
        if add_conn:
            add_conn.close()


# Inserting the metadata of the specified file into the DataBase, while also encrypting the file with Diffie-Hellman and storing it in the appropriate folder
def add_with_DH(file_name):
    before_path = os.path.join(PM.SIMPLE_FILES_PATH, file_name)
    after_path = os.path.join(PM.ENCRYPTED_FILES_PATH, file_name[:-4] + "_encrypted.txt")
    pb_key1, pr_key1, pb_key2, pr_key2 = DH.compute_initial_prime_numbers()

    print("[DIFFIE-HELLMAN] Party 1 has the key pair (" + str(pb_key1) + ", " + str(
        pr_key1) + "), while Party 2 has the key pair (" + str(pb_key2) + ", " + str(pr_key2) + ")")

    DH.encrypt(before_path, after_path, pb_key1, pr_key1, pb_key2, pr_key2)
    size, atime, mtime, ctime = PM.extract_file_metadata(before_path)
    add_conn = sqlite3.connect(DATABASE_PATH)
    try:
        c = add_conn.cursor()
        add_command = """INSERT INTO files(name, encryption_type, encryption_param_1, encryption_param_2, encryption_param_3, encryption_param_4, size, last_access, last_modification, creation_time) VALUES (?,?,?,?,?,?,?,?,?,?)"""
        param_touple = (file_name, "DH", pb_key1, pr_key1, pb_key2, pr_key2, size, atime, mtime, ctime)
        c.execute(add_command, param_touple)
        add_conn.commit()
        print("[SYSTEM] File " + file_name + " added to DataBase using Diffie-Hellman Encryption!")
        c.close()
    except sqlite3.Error as err:
        print("[SYSTEM] Failed to add into SqLite table", err)
    finally:
        if add_conn:
            add_conn.close()


# The method the user will interact with the database. Specifying the file name and the algorithm, we will encrypt the file with the chosen algorithm and add the file metadata to the database
# This method is secured and if something is wrong, an exception will be raised
def add_to_database(file_name, encryption_alg):
    if is_in_database(file_name):
        raise Exception("[SYSTEM] File " + file_name + " is already in DataBase!")
    PM.verify_file(file_name, True)
    if encryption_alg == "RSA":
        add_with_RSA(file_name)
    elif encryption_alg == "DH":
        add_with_DH(file_name)
    else:
        raise Exception("[SYSTEM] Unrecognized encryption algorithm!")


# We decrypt a file encrypted with RSA and we open the decrypted file, after overriding the original file in the appropriate folder
def read_with_RSA(file_name, encrypted_file_name, param1, param2):
    before_path = os.path.join(PM.ENCRYPTED_FILES_PATH, encrypted_file_name)
    after_path = os.path.join(PM.SIMPLE_FILES_PATH, file_name)
    RSA.decrypt(before_path, after_path, param1, param2)
    os.startfile(after_path)


# We decrypt a file encrypted with Diffie-Hellman and we open the decrypted file, after overriding the original file in the appropriate folder
def read_with_DH(file_name, encrypted_file_name, param1, param2, param3, param4):
    before_path = os.path.join(PM.ENCRYPTED_FILES_PATH, encrypted_file_name)
    after_path = os.path.join(PM.SIMPLE_FILES_PATH, file_name)
    DH.decrypt(before_path, after_path, param1, param2, param3, param4)
    os.startfile(after_path)


# The method the users will interact with the DataBase. Being a secured method, it will raise an Exception if something is wrong. We receive the original file name, and we fetch
# the metadata from the database, display it, decrypt the file, store it in the appropriate folder and open the file
def read_from_database(file_name):
    if not is_in_database(file_name):
        raise Exception("[SYSTEM] File " + file_name + " is not in DataBase!")
    PM.verify_file(file_name, True)
    encrypted_file_name = file_name[:-4] + "_encrypted.txt"
    PM.verify_file(encrypted_file_name, False)
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
    except sqlite3.Error as err:
        print("[SYSTEM] Failed to read from SqLite table", err)
    finally:
        if check_conn:
            check_conn.close()
        print(
            "[SYSTEM] File Metadata:\nName: " + metadata[0] + "\nSize: " + str(
                metadata[1]) + " byte(s)\nLast access at: " +
            datetime.fromtimestamp(metadata[2]).strftime('%d-%m-%Y') + "\nLast modification at: " +
            datetime.fromtimestamp(metadata[3]).strftime('%d-%m-%Y') + "\nCreated at: " +
            datetime.fromtimestamp(metadata[4]).strftime('%d-%m-%Y'))
        if encryption_algorithm == "RSA":
            read_with_RSA(file_name, encrypted_file_name, rsa_params[0], rsa_params[1])
        elif encryption_algorithm == "DH":
            read_with_DH(file_name, encrypted_file_name, dh_params[0], dh_params[1], dh_params[2], dh_params[3])
        else:
            raise Exception("[SYSTEM] Error when trying to read file - Invalid encryption algorithm!")


initialize_database()
add_to_database("sample_text.txt", "RSA")
time.sleep(2)
read_from_database("sample_text.txt")
