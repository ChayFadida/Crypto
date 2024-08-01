from hashlib import sha256
import os

class ECElGamal:
    # Elliptic Curve Parameters for secp256k1
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (Gx, Gy)

    def __init__(self):
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        private_key = int.from_bytes(os.urandom(32), 'big') % self.N
        public_key = self.point_multiply(private_key, self.G)
        return private_key, public_key

    def inverse_mod(self, k, p):
        if k == 0:
            raise ZeroDivisionError('division by zero')
        if k < 0:
            return p - self.inverse_mod(-k, p)
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        return old_s % p

    def point_add(self, point1, point2):
        if point1 == (None, None):
            return point2
        if point2 == (None, None):
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return (None, None)

        if x1 == x2:
            m = (3 * x1 * x1) * self.inverse_mod(2 * y1, self.P)
        else:
            m = (y2 - y1) * self.inverse_mod(x2 - x1, self.P)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        x3 = x3 % self.P
        y3 = -y3 % self.P
        return (x3, y3)

    def point_multiply(self, scalar, point):
        result = (None, None)
        addend = point

        while scalar:
            if scalar & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            scalar >>= 1

        return result

    def key_derivation(self, shared_secret_x, length):
        # Derive a key of the necessary length using SHA-256
        key = b""
        counter = 0
        while len(key) < length:
            counter_bytes = counter.to_bytes(4, 'big')
            key += sha256(shared_secret_x.to_bytes(32, 'big') + counter_bytes).digest()
            counter += 1
        return key[:length]

    def encrypt(self, recipient_public_key, message):
        ephemeral_private_key = int.from_bytes(os.urandom(32), 'big') % self.N
        ephemeral_public_key = self.point_multiply(ephemeral_private_key, self.G)
        shared_secret = self.point_multiply(ephemeral_private_key, recipient_public_key)
        shared_secret_key = self.key_derivation(shared_secret[0], len(message))
        ciphertext = bytes([m ^ k for m, k in zip(message, shared_secret_key)])
        return ephemeral_public_key, ciphertext

    def decrypt(self, recipient_private_key, ephemeral_public_key, ciphertext):
        shared_secret = self.point_multiply(recipient_private_key, ephemeral_public_key)
        shared_secret_key = self.key_derivation(shared_secret[0], len(ciphertext))
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, shared_secret_key)])
        return plaintext

# Simulation: Bob sends a message to Alice
def simulate_bob_to_alice():
    # Instantiate Alice's and Bob's ECElGamal systems
    alice = ECElGamal()
    bob = ECElGamal()

    # Bob's message
    message = b"Hello Alice! This is a secret message from Bob."
    print(f"Original Message from Bob: {message}")

    # Bob encrypts the message using Alice's public key and his own private key
    ephemeral_public_key, ciphertext = bob.encrypt(alice.public_key, message)
    print(f"Ciphertext: {ciphertext}")

    # Alice decrypts the message using her private key and Bob's public key
    decrypted_message = alice.decrypt(alice.private_key, ephemeral_public_key, ciphertext)
    print(f"Decrypted Message at Alice's side: {decrypted_message}")

# Run the simulation
simulate_bob_to_alice()
