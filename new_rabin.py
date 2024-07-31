import random
import hashlib
import math

class RabinSignature:
    SECURITY_LEVEL = 1  # Bit length for public key and hash

    @staticmethod
    def is_prime(number):
        """
        Checks if a number is prime.
        """
        if number % 2 == 0 and number > 2:
            return False
        return all(number % i != 0 for i in range(3, int(math.sqrt(number)) + 1, 2))

    @staticmethod
    def hash512(x: bytes) -> bytes:
        hx = hashlib.sha256(x).digest()
        idx = len(hx) // 2
        return hashlib.sha256(hx[:idx]).digest() + hashlib.sha256(hx[idx:]).digest()

    @staticmethod
    def hash_to_int(x: bytes) -> int:
        """Converts hash output to an integer."""
        hx = RabinSignature.hash512(x)
        for i in range(RabinSignature.SECURITY_LEVEL - 1):
            hx += RabinSignature.hash512(hx)
        return int.from_bytes(hx, 'little')

    @staticmethod
    def generate_keys():
        # Generate p and q, both congruent to 3 mod 4
        while True:
            p = 3 + 4 * random.randint(1, 100)
            q = 3 + 4 * random.randint(1, 100)
            if RabinSignature.is_prime(p) and RabinSignature.is_prime(q) and p != q:
                return p, q

    @staticmethod
    def sign_rabin(p: int, q: int, message: bytes) -> tuple:
        n = p * q
        i = 0 
        while True:
            h = RabinSignature.hash_to_int(message + b'\x00' * i) % n
            if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
                break
            i += 1
        lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
        rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
        s = (lp + rp) % n
        return s, i

    @staticmethod
    def verify(n: int, message: bytes, s: int, padding: int) -> bool:
        h = RabinSignature.hash_to_int(message + b'\x00' * padding) % n
        return h == (s * s) % n

    @staticmethod
    def main():
        # Generate keys
        p, q = RabinSignature.generate_keys()
        n = p * q

        print(f"Public key (n): {n}")
        print(f"Private key (p, q): ({p}, {q})")

        # Message to be signed
        message = b"Hello, this is a test message!"

        # Sign the message
        s, padding = RabinSignature.sign_rabin(p, q, message)
        print(f"Signature: {s}")
        print(f"Padding used: {padding}")

        # Verify the signature
        is_valid = RabinSignature.verify(n, message, s, padding)
        print(f"Signature valid: {is_valid}")

if __name__ == "__main__":
    RabinSignature.main()
