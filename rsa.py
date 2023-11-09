"""
RSA example

As discussed in "A Method for Obtaining Digital Signatures and Public Key Cryptosystems"
by Rivest et al.

Issues with this program
- might not implement extended euclid algo when computing e from d
- create blocks char by char (inefficient + no padding)
- does not work with high bit counts + would be slow
- inconsistent typing, comments, etc
"""
from math import gcd, ceil
from random import randrange
import re
from typing import List


# https://stackoverflow.com/questions/34324197/solving-linear-diophantine-equation
def solve_dioph(a, b, c):
    m1 = 1
    m2 = 0
    n1 = 0
    n2 = 1
    r1 = a
    r2 = b
    while r1 % r2 != 0:
        q = r1 // r2
        aux = r1 % r2
        r1 = r2
        r2 = aux
        aux3 = n1 - (n2 * q)
        aux2 = m1 - (m2 * q)
        m1 = m2
        n1 = n2
        m2 = aux2
        n2 = aux3
    return m2 * c, n2 * c


# https://stackoverflow.com/a/69803332
def string_to_int(s):
    return int.from_bytes(s.encode(), byteorder="little")


def int_to_string(i):
    length = ceil(i.bit_length() / 8)
    return i.to_bytes(length, byteorder="little").decode()


def extended_euclid(u: int, v: int):
    """
    Given nonnegative ints u, v,
    return (u_1, u_2, u_3) s.t. uu_1 + vu_2 = u_3 = gcd(u, v)
    """
    (u1, u2, u3) = (1, 0, u)
    (v1, v2, v3) = (0, 1, v)
    while True:
        # print("u\t", (u1, u2, u3), "\t\tv", (v1, v2, v3), "\t\tq", q)
        if v3 == 0:
            break
        q = int(u3 / v3)
        (t1, t2, t3) = (u1 - v1 * q, u2 - v2 * q, u3 - v3 * q)
        (u1, u2, u3) = (v1, v2, v3)
        (v1, v2, v3) = (t1, t2, t3)
    return (u1, u2, u3)


def primality_test(p: int) -> bool:
    """
    return True if prime, False if composite
    """

    def jacobi(a: int, b: int) -> int:
        if a == 0:
            return 0
        if a == 1:
            return 1
        elif a % 2 == 0:
            return jacobi(a // 2, b) * (-1) ** ((b**2 - 1) / 8)
        else:
            return jacobi(b % a, a) * (-1) ** ((a - 1) * (b - 1) / 4)

    # test 100 times against random nums
    for _ in range(100):
        # random number a from distribution
        a = randrange(2, p - 1)
        j = jacobi(a, p)
        if not ((p + j) % p == pow(a, (p - 1) // 2, p) and gcd(a, p) == 1):
            return False
    return True


def generate_prime(n: int) -> int:
    """
    from article
    ---
    We recommend using 100-digit (decimal) prime numbers p and q,
    so that n has 200 digits.
    To find a 100-digit "random" prime number, generate (odd) 100-digit
    random numbers until a prime number is found. By the prime number theorem,
    about (ln 10^100)/2 = 115 numbers will be tested before a prime is found
    ---
    note: this fails with high bit counts bc of precision i think
    """
    is_prime = False
    while not is_prime:
        # 1) generate odd num with n bits
        num = randrange(2 ** (n - 1) + 1, 2**n - 1, 2)
        # 2) Solovay–Strassen primality test
        is_prime = primality_test(num)
    return num


class RSA:
    """
    RSA class
    """

    def __init__(self):
        self.bit_size = 10
        # self.debug = True
        # large prime numbers
        self.p = None
        self.q = None
        # p * q
        self.n = None
        # d is relatively prime to (p-1) * (q-1)
        self.d = None
        self.e = None

    def __str__(self):
        return f"p: {self.p}\nq: {self.q}\nn: {self.n}\ne: {self.e}\nd: {self.d}\n---\nEncryption key: (e, n): {self.e, self.n}\nDecryption key: (d, n): {self.d, self.n}\n---"

    def generate_primes(self):
        """
        Generate prime numbers p, q
        """
        self.p = generate_prime(self.bit_size)
        q = self.p
        # ensure no collision
        while q == self.p:
            q = generate_prime(self.bit_size)
        self.q = q
        self.n = self.p * self.q

    def compute_e_d(self):
        assert self.p is not None
        assert self.q is not None
        assert self.n is not None

        phi = (self.p - 1) * (self.q - 1)

        def compute_d():
            largest_prime = max(self.p, self.q)
            d = 0
            while d < largest_prime:
                # guarantee its larger than largest_prime
                d = generate_prime(self.bit_size + 1)
            return d

        def compute_e(d):
            e = 0
            x = [phi, d]
            while True:
                x.append(x[-2] % x[-1])
                if x[-1] == 0:
                    break

                # temp = extended_euclid(x[-2], x[-1])
                temp = solve_dioph(x[0], x[1], x[-1])

                # (a, b) = temp
                b = temp[1]
                e = b
                # print(f"\tx:\t{x[-1]}\ta:\t{a}\tb:\t{b}")
            return e

        # 1) choose d s.t. it is relatively prime to phi
        # a prime number greater than max(p, q) works
        d = compute_d()
        # 2) calculate e from d
        e = -1
        # they mentioned some condition where you would want to recompute d (and then e)
        # i found that i was generating negative e's sometimes so this prevents that
        # bottom line: not the same condition i don't think
        while e < 0:
            d = compute_d()
            e = compute_e(d)
        self.e = e
        self.d = d

        # check valid values were generated
        assert gcd(phi, self.d) == 1
        assert (self.e * self.d) % phi == 1

    def encrypt(self, m: str) -> List[int]:
        # split into subgroups of length 1 (temporary)
        bins = re.findall(".?", m)
        # convert each bin of 1 char into an integer representation
        # note: doing it char by char simplifies code
        bins = list(map(lambda bin: string_to_int(bin), bins))
        # encrypt each block
        c = list(map(lambda bin: pow(bin, self.e, self.n), bins))
        # if self.debug:
        #     print(f"Computing m^e % n: {int_m}^{self.e} % {self.n}")
        return c

    def decrypt(self, c: str):
        """
        Decrypt cipher text with class decryption key
        """
        # decrypt each block
        c_bins = list(map(lambda bin: pow(bin, self.d, self.n), c))
        # convert int representation to str
        c_bins = list(map(lambda bin: int_to_string(bin), c_bins))
        # concatenate list to get original message
        return "".join(c_bins)


M = "IT'S ALL GREEK TO ME"

my_rsa = RSA()
my_rsa.generate_primes()
my_rsa.compute_e_d()
print(my_rsa)
cipher = my_rsa.encrypt(M)
print(f"Ciphertext: {cipher}")
plain = my_rsa.decrypt(cipher)
print(f"Original message: {plain}")
