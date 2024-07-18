
from struct import Struct, error as struct_error
from itertools import cycle as iter_cycle
import hashlib
import sys
import random
import Hash
# security level 1 means  512 bits public key and hash length
SECURITY_LEVEL = 1

class Rabin(object):

    def gcd(a: int, b: int) -> int:
        if b > a:
            a, b = b, a
        while b > 0:
            a, b = b, a % b
        return a


    def gen_prime_pair(self, seed) -> tuple:
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)

        priv_range = 2 ** (256 * SECURITY_LEVEL)
        p = self.next_prime(self.hash_to_int(seed) % priv_range)
        q = self.next_prime(self.hash_to_int(seed + b'\x00') % priv_range)
        return (p, q)


    def next_prime(self, p: int) -> int:
        while p % 4 != 3:
            p = p + 1
        return self.next_prime_3(p)


    def next_prime_3(self, p: int) -> int:
        m_ = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29
        while self.gcd(p, m_) != 1:
            p = p + 4
        if pow(2, p - 1, p) != 1 or pow(3, p - 1, p) != 1 or pow(5, p - 1, p) != 1 or pow(17, p - 1, p) != 1:
            return self.next_prime_3(p + 4)
        return p


    def hash512(self, x: bytes) -> bytes:
        hx = hashlib.sha256(x).digest()
        idx = len(hx) // 2
        return hashlib.sha256(hx[:idx]).digest() + hashlib.sha256(hx[idx:]).digest()


    def hash_to_int(self, x: bytes) -> int:
        hx = self.hash512(x)
        for _ in range(SECURITY_LEVEL - 1):
            hx += self.hash512(hx)
        return int.from_bytes(hx, 'little')


    def sign_rabin(self, p: int, q: int, digest: bytes) -> tuple:
        """
        :param p: part of private key
        :param q: part of private key
        :param digest: message digest to sign
        :return: rabin signature (S: int, padding: int)
        """
        n = p * q
        i = 0
        while True:
            h = self.hash_to_int(digest + b'\x00' * i) % n
            if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
                break
            i += 1
        lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
        rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
        s = (lp + rp) % n
        return s, i


    def verify_rabin(self, n: int, digest: bytes, s: int, padding: int) -> bool:
        """
        :param n: rabin public key
        :param digest: digest of signed message
        :param s: S of signature
        :param padding: the number of padding bytes
        """
        return self.hash_to_int(digest + b'\x00' * padding) % n == (s * s) % n


    def write_number(self, number: int, filename: str) -> None:
        with open(f'{filename}.txt', 'w') as f:
            f.write('%d' % number)


    def read_number(self, filename: str) -> int:
        with open(f'{filename}.txt', 'r') as f:
            return int(f.read())


    def sign(self, hex_message: str, p=None, q=None) -> tuple:
        if not p:
            p = self.read_number('p')
        if not q:
            q = self.read_number('q')
        return self.sign_rabin(p, q, bytes.fromhex(hex_message))


    def verify(self,hex_message: str, padding: str, hex_signature: str, n=None):
        if not n:
            n = self.read_number('n')
        return self.verify_rabin(n, bytes.fromhex(hex_message), int(hex_signature, 16), int(padding))