import random

import EncryptionConstants

PATH = "sample_text.txt"


# This function computes four large prime numbers representing the communicating parties' private and public keys
# I chose DIFFIE_HELLMAN_KEY_SIZE = 16, same as RSA encryption, since it is the most efficient
def compute_initial_prime_numbers():
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


# Based on the generated prime number keys, we can compute the partial keys for the 2 communicating parties
# This is calculated by computing (pubKey1 ^ private_key) mod pubKey2. Thus, using large numbers, there are an infinite amount of possible values
# whose modulo can be either partial_key1 or partial_key2, rendering an attack ineffective, due to the lack of information of the attacker
def generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2):
    partial_key1 = pub_key1 ** priv_key1
    partial_key1 %= pub_key2
    partial_key2 = pub_key1 ** priv_key2
    partial_key2 %= pub_key2
    return partial_key1, partial_key2


# Now, in order for each party to receive the same full key, we need to compute (partial_key of the other party)^ (private_key of current party) mod public_key2. Both ends
# will now have the same key, and encryption can begin
def generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2):
    full_key_1 = partial_key2 ** priv_key1
    full_key_1 %= pub_key2
    full_key_2 = partial_key1 ** priv_key2
    full_key_2 %= pub_key2
    if full_key_1 != full_key_2:
        raise Exception("Encryption failed!")
    return full_key_1


# For DH encryption, we are simply going to add the full_key to each character's ASCII value, obtaining a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the original file
def encrypt(path, pub_key1, priv_key1, pub_key2, priv_key2):
    partial_key1, partial_key2 = generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2)
    print("[DH ENCRYPTION] The two partial keys are " + str(partial_key1) + " and " + str(partial_key2))
    full_key = generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2)
    print("[DH ENCRYPTION] The full key is " + str(full_key))
    file = open(path, "r")
    plaintext = file.read()
    print("[DH ENCRYPTION] Plaintext is \'" + plaintext + "\'")
    ascii_characters = [ord(ch) for ch in plaintext]
    encoded_numbers = [chval + full_key for chval in ascii_characters]
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[DH ENCRYPTION] Ciphertext is \'" + ciphertext + "\'")

    with open(str(path) + "_encrypted", "w") as output_file:
        output_file.write('\n'.join(str(number) for number in encoded_numbers))


# For DH decryption, we will decrypt the ciphertext by subtracting the full key from each character's ASCII value. We will obtain a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the encoded file
def decrypt(path, pub_key1, priv_key1, pub_key2, priv_key2):
    partial_key1, partial_key2 = generate_partial_keys(pub_key1, priv_key1, pub_key2, priv_key2)
    print("[DH DECRYPTION] The two partial keys are " + str(partial_key1) + " and " + str(partial_key2))
    full_key = generate_full_key(priv_key1, partial_key1, pub_key2, priv_key2, partial_key2)
    print("[DH DECRYPTION] The full key is " + str(full_key))
    encoded_numbers = []
    file = open(path, "r")
    for line in file:
        encoded_numbers.append(int(line.strip('\n')))
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[DH DECRYPTION] Ciphertext is \'" + ciphertext + "\'")
    decoded_characters = [chr(chval - full_key) for chval in encoded_numbers]
    plaintext = ""
    for x in decoded_characters:
        plaintext += x
    print("[DH DECRYPTION] Plaintext is \'" + plaintext + "\'")

    with open(str(path)[:-10] + "_decrypted", "w") as output_file:
        output_file.write(plaintext)


pb_key1, pr_key1, pb_key2, pr_key2 = compute_initial_prime_numbers()

print("[DIFFIE-HELLMAN] Party 1 has the key pair (" + str(pb_key1) + ", " + str(
    pr_key1) + "), while Party 2 has the key pair (" + str(pb_key2) + ", " + str(pr_key2) + ")")

encrypt(EncryptionConstants.PATH, pb_key1, pr_key1, pb_key2, pr_key2)

decrypt(str(EncryptionConstants.PATH) + "_encrypted", pb_key1, pr_key1, pb_key2, pr_key2)
