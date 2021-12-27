import random

import EncryptionConstants


# This function computes two large enough prime numbers (!!! that will need to be added to the database so that decryption can take place!!!)
# such that n (the RSA modulus) does not exceed 2^KEY_SIZE
# I chose RSA_KEY_SIZE = 16, since if it was chosen above 24, the algorithm would lose efficiency
def compute_initial_prime_numbers():
    primes_in_range = EncryptionConstants.generate_primes(EncryptionConstants.LOWER_BOUND,
                                                          EncryptionConstants.RSA_UPPER_BOUND)
    p1 = 0
    p2 = 0
    while p1 == p2 or (p1 * p2) > 2 ** EncryptionConstants.RSA_KEY_SIZE:
        p1 = random.choice(primes_in_range)
        p2 = random.choice(primes_in_range)
    return p1, p2


# This function computes the RSA modulus value and the Euler's totient function value
def compute_n_and_totient(p1, p2):
    return p1 * p2, (p1 - 1) * (p2 - 1)


# This function computed the e value, which is a part of the public key
def compute_e(t):
    public_exponent = 0
    # I chose to proceed this way since it is more efficient to have a small e instead of a large one
    for e_value in range(3, t - 1):
        if EncryptionConstants.gcd(e_value, t) == 1:
            public_exponent = e_value
            break
    return public_exponent


# This function computed the d value, which is a part of the private key
def compute_d(e_value, t):
    gcd_value, x, y = EncryptionConstants.extended_gcd(e_value, t)
    if gcd_value != 1:
        raise ValueError("Something went wrong with the e value computation!")
    return x % t


# RSA encryption is ((message)**e) mod n
# Thus, we will encrypt the plaintext by encrypting each character's ASCII value. We will obtain a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the original file
def encrypt(path, prime1, prime2):
    n_value, totient = compute_n_and_totient(prime1, prime2)
    public_exponent = compute_e(totient)
    print("[RSA ENCRYPTION] The public key is (" + str(public_exponent) + ", " + str(n_value) + ")")
    file = open(path, "r")
    plaintext = file.read()
    print("[RSA ENCRYPTION] Plaintext is \'" + plaintext + "\'")
    ascii_characters = [ord(ch) for ch in plaintext]
    encoded_numbers = [((chval ** public_exponent) % n_value) for chval in ascii_characters]
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[RSA ENCRYPTION] Ciphertext is \'" + ciphertext + "\'")

    with open(str(path) + "_encrypted", "w") as output_file:
        output_file.write('\n'.join(str(number) for number in encoded_numbers))


# RSA decryption is ((cipher_message)**d) mod n
# Thus, we will decrypt the ciphertext by decrypting each character's ASCII value. We will obtain a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the encoded file
def decrypt(path, prime1, prime2):
    n_value, totient = compute_n_and_totient(prime1, prime2)
    e = compute_e(totient)
    private_exponent = compute_d(e, totient)
    print("[RSA DECRYPTION] The private key is (" + str(private_exponent) + ", " + str(n_value) + ")")
    encoded_numbers = []
    file = open(path, "r")
    for line in file:
        encoded_numbers.append(int(line.strip('\n')))
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[RSA DECRYPTION] Ciphertext is \'" + ciphertext + "\'")
    decoded_characters = [chr((chval ** private_exponent) % n_value) for chval in encoded_numbers]
    plaintext = ""
    for x in decoded_characters:
        plaintext += x
    print("[RSA DECRYPTION] Plaintext is \'" + plaintext + "\'")

    with open(str(path)[:-10] + "_decrypted", "w") as output_file:
        output_file.write(plaintext)


# Let's test our RSA encryption algorithm implementation for a sample text file!
prim1, prim2 = compute_initial_prime_numbers()

print("[RSA] The two selected prime numbers are: " + str(prim1) + " and " + str(prim2))

encrypt(EncryptionConstants.PATH, prim1, prim2)

decrypt(str(EncryptionConstants.PATH) + "_encrypted", prim1, prim2)
