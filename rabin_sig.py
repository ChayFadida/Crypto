import random
from sympy import mod_inverse, isprime, sqrt_mod

def generate_prime(bits):
    """
    Generate a prime number of the specified bit length.
    
    Parameters:
        bits (int): The bit length of the prime number.
        
    Returns:
        int: A prime number of the specified bit length.
    """
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def generate_keys(bits=64):
    """
    Generate public and private keys for the Rabin signature algorithm.
    
    Parameters:
        bits (int): The bit length of the prime numbers p and q.
        
    Returns:
        tuple: Public key (n) and private keys (p, q).
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    return (n, p, q)

def hash_function(message):
    """
    Simple hash function for demonstration purposes.
    d
    Parameters:
        message (str): The message to hash.
        
    Returns:
        int: The hash of the message modulo n.
    """
    return int.from_bytes(message.encode(), 'big') % n

def sign(message, p, q):
    """
    Generate a Rabin signature for a given message using private keys p and q.
    
    Parameters:
        message (str): The message to sign.
        p (int): The prime number p.
        q (int): The prime number q.
        
    Returns:
        int: The Rabin signature of the message.
        
    Raises:
        ValueError: If no square root exists for the given hash modulo n.
    """
    H = hash_function(message)
    n = p * q
    s = sqrt_mod(H, n)
    if s is None:
        raise ValueError("No square root exists for the given hash modulo n.")
    return s

def verify(message, signature, n):
    """
    Verify a Rabin signature for a given message.
    
    Parameters:
        message (str): The message to verify.
        signature (int): The Rabin signature.
        n (int): The public key n.
        
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    H = hash_function(message)
    return pow(signature, 2, n) == H

# Example usage
message = "This is a secret message."

# Key Generation
print("Generating keys...")
n, p, q = generate_keys()

print(f"Public key (n): {n}")
print(f"Private key (p, q): ({p}, {q})")

# Signing
print("Signing the message...")
signature = sign(message, p, q)
print(f"Signature: {signature}")

# Verification
print("Verifying the signature...")
is_valid = verify(message, signature, n)
print(f"Signature valid: {is_valid}")