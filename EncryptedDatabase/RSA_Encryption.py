import math
import random

KEY_SIZE = 16
# LOWER BOUND for prime number generation
LOWER_BOUND = 3
# UPPER BOUND for prime number generation
UPPER_BOUND = int(2 ** KEY_SIZE / 2)
PATH = "sample_text.txt"


# This function computed the d value, which is a part of the private key
def compute_d(e_value, t):
    gcd_value, x, y = extended_gcd(e_value, t)
    if gcd_value != 1:
        raise ValueError("Something went wrong with the e value computation!")
    return x % t


# This function applies the Extended Euclidean algorithm on two values. This operation is needed when computing the d value,
# component of the private key, since ed = 1 mod totient, where e is a component of the public key
def extended_gcd(a, b):
    x, last_x, y, last_y = 0, 1, 1, 0
    while b:
        a, (quotient, b) = b, divmod(a, b)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y
    return a, last_x, last_y


# This function computed the greatest common divisor between two numbers
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


# This function computed the e value, which is a part of the public key
def compute_e(t):
    public_exponent = 0
    # I chose to proceed this way since it is more efficient to have a small e instead of a large one
    for e_value in range(3, t - 1):
        if gcd(e_value, t) == 1:
            public_exponent = e_value
            break
    return public_exponent


# This function computes the RSA modulus value and the Euler's totient function value
def compute_n_and_totient(p1, p2):
    return p1 * p2, (p1 - 1) * (p2 - 1)


# This function computes two large enough prime numbers (!!! that will need to be added to the database so that decryption can take place!!!)
# such that n (the RSA modulus) does not exceed 2^KEY_SIZE
# I chose KEY_SIZE = 16, since if it was chosen above 24, the algorithm would lose efficiency
def compute_initial_prime_numbers():
    primes_in_range = generate_primes()
    p1 = 0
    p2 = 0
    while p1 == p2 or (p1 * p2) > 2 ** KEY_SIZE:
        p1 = random.choice(primes_in_range)
        p2 = random.choice(primes_in_range)
    return p1, p2


# Generates all the prime numbers between the lower and upper bound, depending on the key size
def generate_primes():
    generated_primes = []
    for num in range(LOWER_BOUND, UPPER_BOUND + 1, 2):
        if all(num % i != 0 for i in range(2, int(math.sqrt(num)) + 1)):
            generated_primes.append(num)
    return generated_primes


# RSA encryption is ((message)**e) mod n
# Thus, we will encrypt the plaintext by encrypting each character's ASCII value. We will obtain a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the original file
def encrypt(path, public_exponent, n_value):
    file = open(path, "r")
    plaintext = file.read()
    print("[ENCRYPTION] Plaintext is \'" + plaintext + "\'")
    ascii_characters = [ord(ch) for ch in plaintext]
    encoded_numbers = [((chval ** public_exponent) % n_value) for chval in ascii_characters]
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[ENCRYPTION] Ciphertext is \'" + ciphertext + "\'")

    with open(str(path) + "_encrypted", "w") as output_file:
        output_file.write('\n'.join(str(number) for number in encoded_numbers))


# RSA decryption is ((cipher_message)**d) mod n
# Thus, we will decrypt the ciphertext by decrypting each character's ASCII value. We will obtain a sequence of numbers
# which we will then turn back to characters and write the result in a separate file
# Path refers to the path of the encoded file
def decrypt(path, private_exponent, n_value):
    encoded_numbers = []
    file = open(path, "r")
    for line in file:
        encoded_numbers.append(int(line.strip('\n')))
    ciphertext = ""
    for x in encoded_numbers:
        ciphertext += str(x)
    print("[DECRYPTION] Ciphertext is \'" + ciphertext + "\'")
    decoded_characters = [chr((chval ** private_exponent) % n_value) for chval in encoded_numbers]
    plaintext = ""
    for x in decoded_characters:
        plaintext += x
    print("[DECRYPTION] Plaintext is \'" + plaintext + "\'")

    with open(str(path)[:-10] + "_decrypted", "w") as output_file:
        output_file.write(plaintext)


# Let's test our RSA encryption algorithm implementation for a sample text file!
prime1, prime2 = compute_initial_prime_numbers()
print("The two selected prime numbers are: " + str(prime1) + " and " + str(prime2))
n, totient = compute_n_and_totient(prime1, prime2)
print("The n value is " + str(n) + ", and the totient is " + str(totient))
e = compute_e(totient)
print("The public key is (" + str(e) + ", " + str(n) + ")")
d = compute_d(e, totient)
print("The private key is (" + str(d) + ", " + str(n) + ")")

encrypt(PATH, e, n)

decrypt(str(PATH) + "_encrypted", d, n)
