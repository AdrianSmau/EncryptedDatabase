import math

RSA_KEY_SIZE = 16
DIFFIE_HELLMAN_KEY_SIZE = 16
# LOWER BOUND for prime number generation
LOWER_BOUND = 3
# UPPER BOUND for prime number generation
RSA_UPPER_BOUND = int(2 ** RSA_KEY_SIZE / 2)
DIFFIE_HELLMAN_UPPER_BOUND = int(2 ** DIFFIE_HELLMAN_KEY_SIZE / 2)


# This function computed the greatest common divisor between two numbers
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


# This function applies the Extended Euclidean algorithm on two values. For RSA, This operation is needed when computing the d value,
# component of the private key, since ed = 1 mod totient, where e is a component of the public key
def extended_gcd(a, b):
    x, last_x, y, last_y = 0, 1, 1, 0
    while b:
        a, (quotient, b) = b, divmod(a, b)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y
    return a, last_x, last_y


# Generates all the prime numbers between the lower and upper bound, depending on the key size
def generate_primes(lower_bound, upper_bound):
    generated_primes = []
    for num in range(lower_bound, upper_bound + 1, 2):
        if all(num % i != 0 for i in range(2, int(math.sqrt(num)) + 1)):
            generated_primes.append(num)
    return generated_primes
