from tkinter import Tk
from tkinter.filedialog import askopenfilename

from Database import DB_Functions as DB
from FileInteractionMethods import ParsingMethods as PM


def start():
    """
    Runs the command line and parses the commands, receiving parameters where it makes sense.
    Until the 'quit' command is typed or the program is terminated by force, the loop will continue to receive feedback from the user.
    The Command Line begins by wiping the database clean (along with the Encrypted folder), however this can be skipped.
    The 'help' command will give more information about syntax.
    """
    # Comment if no initialization is wanted
    DB.initialize_database()
    print(
        f"{PM.ConsoleColors.INFO}[COMMAND LINE] Welcome to EncryptedDatabase! Type 'help' for further information!{PM.ConsoleColors.ENDCHAR}")
    while True:
        command = input("cmd> ")
        args = command.split(" ")
        if len(args) == 0:
            print(f"{PM.ConsoleColors.ERROR}Command cannot be null! Try again!{PM.ConsoleColors.ENDCHAR}")
            continue
        action = args[0]
        if len(args) > 2:
            print(
                f"{PM.ConsoleColors.WARNING}[COMMAND LINE] No command requires more than 1 parameter! Ignoring everything from the first parameter forward!...{PM.ConsoleColors.ENDCHAR}")
        if action == "add":
            if len(args) < 2:
                print(f"{PM.ConsoleColors.ERROR}Insufficient parameters! Try again!{PM.ConsoleColors.ENDCHAR}")
                continue
            param = args[1].lower()
            print(
                f"{PM.ConsoleColors.INFO}[COMMAND LINE] Prompting dialog window in order to select chosen file path!...{PM.ConsoleColors.ENDCHAR}")
            root = Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            file_path = askopenfilename(parent=root, filetypes=[("Text files", "*.txt")])
            print(
                f"{PM.ConsoleColors.INFO}[COMMAND LINE] You have chosen the '{file_path}' path!...{PM.ConsoleColors.ENDCHAR}")
            if param != "rsa" and param != "dh":
                print(
                    f"{PM.ConsoleColors.WARNING}[SYSTEM] Unrecognized encryption algorithm! Using RSA by default!{PM.ConsoleColors.ENDCHAR}")
                param = "rsa"
            DB.add_to_database(file_path, param)
        elif action == "list":
            if len(args) == 2:
                print(f"{PM.ConsoleColors.INFO}Ignoring second parameter!{PM.ConsoleColors.ENDCHAR}")
            DB.list_all()
        elif action == "read":
            if len(args) < 2:
                print(f"{PM.ConsoleColors.ERROR}Insufficient parameters! Try again!{PM.ConsoleColors.ENDCHAR}")
                continue
            param = args[1]
            print(
                f"{PM.ConsoleColors.INFO}[COMMAND LINE] You have chosen to read the file '{param}' from the Database!...{PM.ConsoleColors.ENDCHAR}")
            DB.read_from_database(param)
        elif action == "delete":
            if len(args) < 2:
                print(f"{PM.ConsoleColors.ERROR}Insufficient parameters! Try again!{PM.ConsoleColors.ENDCHAR}")
                continue
            param = args[1]
            print(
                f"{PM.ConsoleColors.INFO}[COMMAND LINE] You have chosen to delete the file '{param}' from the Database, and also from the Encrypted Files folder!...{PM.ConsoleColors.ENDCHAR}")
            DB.delete_from_database(param)
        elif action == "help":
            print(
                f"{PM.ConsoleColors.METADATA}This application allows you to store metadata about certain files in a Database, while caching the file in the Files directory! Once a file is added, is it encrypted and stored in the Files.Encrypted directory, and its metadata is stored alongside the encryption method used and parameters used for encryption/decryption!\n*The Database entries are uniquely identified by file name. That means that if you want to add a file with the same name as an existing one, you need to first delete it from the database. Files stored in the Files folder, where cached files are stored, can be overwritten!\nThe commands are:\n[ADD] add (encryption_method) - Prompts a dialog window where you navigate to the chosen file and select it. Using the selected encryption method - either RSA or DH (Diffie-Hellman), we store a copy of your file to the Files directory, we encrypt it and we store it in the Database.\n[LIST ALL FILES] list - Displays all files' names from the Database.\n[READ] read (file_name) - Fetch information about the selected file from the Database, decrypt it from the Encryption file stored when added and replaced with the cached version. Also opens file so the decrypted content can be seen.\n[DELETE] delete (file_name) - deletes the file entry from the Database, and removes its encrypted version from the Encrypted folder. The cached copy from the Files directory still remains, in case the user wants to add it again.\n[QUIT] quit - Terminates application.{PM.ConsoleColors.ENDCHAR}")
        elif action == "quit":
            print(
                f"{PM.ConsoleColors.INFO}[COMMAND LINE] You have chosen to quit the application! Terminating...{PM.ConsoleColors.ENDCHAR}")
            break
        else:
            print(
                f"{PM.ConsoleColors.ERROR}[COMMAND LINE] Unrecognized command! Try again!...{PM.ConsoleColors.ENDCHAR}")
