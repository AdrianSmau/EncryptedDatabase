import os.path
import random

import FileInteractionMethods.ParsingMethods as PM
from FileInteractionMethods.EncryptionMethods import EncryptionConstants


def compute_initial_prime_numbers():
    """
    This function computes two large enough prime numbers such that n (the RSA modulus) does not exceed 2^KEY_SIZE.
    I chose RSA_KEY_SIZE = 16, since if it was chosen above 24, the algorithm would lose efficiency.
    :return: The two chosen prime numbers
    """
    primes_in_range = EncryptionConstants.generate_primes(EncryptionConstants.LOWER_BOUND,
                                                          EncryptionConstants.RSA_UPPER_BOUND)
    p1 = 0
    p2 = 0
    while p1 == p2 or (p1 * p2) > 2 ** EncryptionConstants.RSA_KEY_SIZE:
        p1 = random.choice(primes_in_range)
        p2 = random.choice(primes_in_range)
    return p1, p2


def compute_n_and_totient(p1, p2):
    """
    This function computes the RSA modulus value and the Euler's totient function value
    :param p1: The first prime number chosen (stored in Database)
    :param p2: The second prime number chosen (stored in Database)
    :return: A touple of n, respectively the totient
    """
    return p1 * p2, (p1 - 1) * (p2 - 1)


def compute_e(t):
    """
    This function computed the e value, which is a part of the public key
    :param t: The totient resulted from the above function
    :return: The e value, part of the public key
    """
    public_exponent = 0
    # I chose to proceed this way since it is more efficient to have a small e instead of a large one
    for e_value in range(3, t - 1):
        if EncryptionConstants.gcd(e_value, t) == 1:
            public_exponent = e_value
            break
    return public_exponent


def compute_d(e_value, t):
    """
    This function computed the d value, which is a part of the private key
    :param e_value: The e value, computed using the above method
    :param t: The totient resulted from the two prime numbers
    :return: The d value, part of the private key
    """
    gcd_value, x, y = EncryptionConstants.extended_gcd(e_value, t)
    if gcd_value != 1:
        raise ValueError("Something went wrong with the e value computation!")
    return x % t


def encrypt(before_path, after_path, prime1, prime2):
    """
    RSA encryption is ((message)**e) mod n.
    Thus, we will encrypt the plaintext by encrypting each character's ASCII value.
    We will obtain a sequence of numbers which we will then turn back to characters and write the result in a separate file.
    :param before_path: Path of the original file, the cached version from the Files/ folder
    :param after_path: Path of the encrypted file, from the Files/Encrypted/ folder, where we will store the encrypted version of the file - with '_encrypted' added to the end of the original file name
    :param prime1: The first prime number generated (stored in the Database)
    :param prime2: The second prime number generated (stored in the Database)
    """
    n_value, totient = compute_n_and_totient(prime1, prime2)
    public_exponent = compute_e(totient)
    print(
        f"{PM.ConsoleColors.INFO}[RSA ENCRYPTION] The public key is ({str(public_exponent)},{str(n_value)}){PM.ConsoleColors.ENDCHAR}")
    file = open(before_path, "r")
    plaintext = file.read()
    print(f"{PM.ConsoleColors.INFO}[RSA ENCRYPTION] Plaintext is '{plaintext}'{PM.ConsoleColors.ENDCHAR}")
    ascii_characters = [ord(ch) for ch in plaintext]
    encoded_numbers = [((chval ** public_exponent) % n_value) for chval in ascii_characters]
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print(f"{PM.ConsoleColors.INFO}[RSA ENCRYPTION] Ciphertext is '{ciphertext}'{PM.ConsoleColors.ENDCHAR}")

    with open(after_path, "w") as output_file:
        output_file.write('\n'.join(str(number) for number in encoded_numbers))


def decrypt(before_path, after_path, prime1, prime2):
    """
    RSA decryption is ((cipher_message)**d) mod n.
    Thus, we will decrypt the ciphertext by decrypting each character's ASCII value. We will obtain a sequence of numbers which we will then turn back to characters and write the result in a separate file.
    :param before_path: Path of the encrypted file, from the Files/Encrypted/ folder, where we have stored the encrypted version of the file - with '_encrypted' added to the end of the original file name
    :param after_path: Path of the decrypted file, which will overwrite the cached version from the Files/ folder
    :param prime1: The first prime number generated (stored in the Database)
    :param prime2: The second prime number generated (stored in the Database)
    :returns: True if the decryption went good, False otherwise
    """
    if not os.path.exists(before_path):
        print(f"{PM.ConsoleColors.ERROR}[RSA] Encrypted file does not exist!{PM.ConsoleColors.ENDCHAR}")
        return False
    if not os.path.exists(after_path):
        print(
            f"{PM.ConsoleColors.WARNING}[RSA] The file was deleted from the cache folder! It will now be restored!{PM.ConsoleColors.ENDCHAR}")
    else:
        os.remove(after_path)
    n_value, totient = compute_n_and_totient(prime1, prime2)
    e = compute_e(totient)
    private_exponent = compute_d(e, totient)
    print(
        f"{PM.ConsoleColors.INFO}[RSA DECRYPTION] The private key is ({str(private_exponent)},{str(n_value)}){PM.ConsoleColors.ENDCHAR}")
    encoded_numbers = []
    file = open(before_path, "r")
    for line in file:
        encoded_numbers.append(int(line.strip('\n')))
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print(f"{PM.ConsoleColors.INFO}[RSA DECRYPTION] Ciphertext is '{ciphertext}'{PM.ConsoleColors.ENDCHAR}")
    decoded_characters = [chr((chval ** private_exponent) % n_value) for chval in encoded_numbers]
    plaintext = ""
    for x in decoded_characters:
        plaintext += x
    print(f"{PM.ConsoleColors.INFO}[RSA DECRYPTION] Plaintext is '{plaintext}'{PM.ConsoleColors.ENDCHAR}")

    with open(after_path, "w") as output_file:
        output_file.write(plaintext)

    return True
