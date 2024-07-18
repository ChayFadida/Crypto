from ElGamal import ElGamal

def main():
    elgamal = ElGamal()
    
    # Generate public and private key
    priv_key = elgamal.gen_pubKey()
    
    # Define the message (audio data)
    msg = 32445
    
    # Encrypt the message using the ElGamal encryption algorithm
    encrypted_message = elgamal.encryption(priv_key, msg)

    print("Public Key: ", priv_key)
    print("Encrypted Message: ", encrypted_message)

if __name__ == "__main__":
    main()