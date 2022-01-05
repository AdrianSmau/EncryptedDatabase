import os.path
import random

from FileInteractionMethods import ParsingMethods as PM
from FileInteractionMethods.EncryptionMethods import EncryptionConstants


def compute_initial_prime_numbers():
    """
    This function computes four (relatively) large prime numbers representing the communicating parties' private and public keys by first computing all the 16-bit possible prime numbers, then randomly choosing 4 different ones.
    I chose DIFFIE_HELLMAN_KEY_SIZE = 16, same as RSA encryption, since it is the most efficient
    :return: A touple of the generated numbers
    """
    primes_in_range = EncryptionConstants.generate_primes(EncryptionConstants.LOWER_BOUND,
                                                          EncryptionConstants.DIFFIE_HELLMAN_UPPER_BOUND)
    priv_key1 = 0
    pub_key1 = 0
    priv_key2 = 0
    pub_key2 = 0
    while priv_key1 == pub_key1 or priv_key1 == priv_key2 or priv_key1 == pub_key2 or pub_key1 == priv_key2 or pub_key1 == pub_key2 or priv_key2 == pub_key2:
        priv_key1 = random.choice(primes_in_range)
        pub_key1 = random.choice(primes_in_range)
        priv_key2 = random.choice(primes_in_range)
        pub_key2 = random.choice(primes_in_range)
    return pub_key1, priv_key1, pub_key2, priv_key2


def generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2):
    """
    Based on the generated prime number keys, we can compute the partial keys for the 2 communicating parties.
    This is calculated by computing (pubKey1 ^ private_key) mod pubKey2. Thus, using large numbers, there are an infinite amount of possible values whose modulo can be either partial_key1 or partial_key2, rendering an attack ineffective, due to the lack of information of the attacker.
    :param pub_key1: Public key of the first party
    :param priv_key1: Private key of the first party
    :param pub_key2: Public key of the second party
    :param priv_key2: Private key of the second party
    :return: A touple with the partial keys of both the first and the second parties
    """
    partial_key1 = pub_key1 ** priv_key1
    partial_key1 %= pub_key2
    partial_key2 = pub_key1 ** priv_key2
    partial_key2 %= pub_key2
    return partial_key1, partial_key2


def generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2):
    """
    In order for each party to receive the same full key, we need to compute (partial_key of the other party)^ (private_key of current party) mod public_key2.
    Both ends will now have the same key, and encryption can begin.
    :param priv_key1: Private key of the first party
    :param partial_key1: Partial key of the first party
    :param pub_key2: Public key of the second party
    :param priv_key2: Private key of the second party
    :param partial_key2: Partial key of the second party
    The method raises an Exception if the generated full keys are different from one another, which would mean there is something wrong with the algorithm.
    :return: The full key shared by both ends
    """
    full_key_1 = partial_key2 ** priv_key1
    full_key_1 %= pub_key2
    full_key_2 = partial_key1 ** priv_key2
    full_key_2 %= pub_key2
    if full_key_1 != full_key_2:
        raise Exception("Encryption failed!")
    return full_key_1


def encrypt(before_path, after_path, pub_key1, priv_key1, pub_key2, priv_key2):
    """
    For DH encryption, we are simply going to add the full_key to each character's ASCII value, obtaining a sequence of numbers which we will then turn back to characters and write the result in a separate file.
    :param before_path: Path of the original file, the cached version from the Files/ folder
    :param after_path: Path of the encrypted file, from the Files/Encrypted/ folder, where we will store the encrypted version of the file - with '_encrypted' added to the end of the original file name
    :param pub_key1: Public key of the first party (stored in Database)
    :param priv_key1: Private key of the first party (stored in Database)
    :param pub_key2: Public key of the second party (stored in Database)
    :param priv_key2: Private key of the second party (stored in Database)
    """
    partial_key1, partial_key2 = generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2)
    print(
        f"{PM.ConsoleColors.INFO}[DH ENCRYPTION] The two partial keys are {str(partial_key1)} and {str(partial_key2)}{PM.ConsoleColors.ENDCHAR}")
    full_key = generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2)
    print(f"{PM.ConsoleColors.INFO}[DH ENCRYPTION] The full key is {str(full_key)}{PM.ConsoleColors.ENDCHAR}")
    file = open(before_path, "r")
    plaintext = file.read()
    print(f"{PM.ConsoleColors.INFO}[DH ENCRYPTION] Plaintext is '{plaintext}'{PM.ConsoleColors.ENDCHAR}")
    ascii_characters = [ord(ch) for ch in plaintext]
    encoded_numbers = [chval + full_key for chval in ascii_characters]
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print(f"{PM.ConsoleColors.INFO}[DH ENCRYPTION] Ciphertext is '{ciphertext}'{PM.ConsoleColors.ENDCHAR}")

    with open(after_path, "w") as output_file:
        output_file.write('\n'.join(str(number) for number in encoded_numbers))


def decrypt(before_path, after_path, pub_key1, priv_key1, pub_key2, priv_key2):
    """
    For DH decryption, we will decrypt the ciphertext by subtracting the full key from each character's ASCII value. We will obtain a sequence of numbers which we will then turn back to characters and write the result in a separate file.
    :param before_path: Path of the encrypted file, from the Files/Encrypted/ folder, where we have stored the encrypted version of the file - with '_encrypted' added to the end of the original file name
    :param after_path: Path of the decrypted file, which will overwrite the cached version from the Files/ folder
    :param pub_key1: Public key of the first party (stored in Database)
    :param priv_key1: Private key of the first party (stored in Database)
    :param pub_key2: Public key of the second party (stored in Database)
    :param priv_key2: Private key of the second party (stored in Database)
    :returns: True if the decryption went good, False otherwise
    """
    if not os.path.exists(before_path):
        print(f"{PM.ConsoleColors.ERROR}[DH] Encrypted file does not exist!{PM.ConsoleColors.ENDCHAR}")
        return False
    if not os.path.exists(after_path):
        print(
            f"{PM.ConsoleColors.WARNING}[DH] The file was deleted from the cache folder! It will now be restored!{PM.ConsoleColors.ENDCHAR}")
    else:
        os.remove(after_path)
    partial_key1, partial_key2 = generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2)
    print(
        f"{PM.ConsoleColors.INFO}[DH DECRYPTION] The two partial keys are {str(partial_key1)} and {str(partial_key2)}{PM.ConsoleColors.ENDCHAR}")
    full_key = generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2)
    print(f"{PM.ConsoleColors.INFO}[DH DECRYPTION] The full key is {str(full_key)}{PM.ConsoleColors.ENDCHAR}")
    encoded_numbers = []
    file = open(before_path, "r")
    for line in file:
        encoded_numbers.append(int(line.strip('\n')))
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print(f"{PM.ConsoleColors.INFO}[DH DECRYPTION] Ciphertext is '{ciphertext}'{PM.ConsoleColors.ENDCHAR}")
    decoded_characters = [chr(chval - full_key) for chval in encoded_numbers]
    plaintext = ""
    for x in decoded_characters:
        plaintext += x
    print(f"{PM.ConsoleColors.INFO}[DH DECRYPTION] Plaintext is '{plaintext}'{PM.ConsoleColors.ENDCHAR}")

    with open(after_path, "w") as output_file:
        output_file.write(plaintext)

    return True
