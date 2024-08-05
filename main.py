import wave
import struct
import numpy as np
import sounddevice as sd
from blowfish import BlowFish
from os import urandom
from rabin_sig import RabinSignature
from ElGamal import ECElGamal

# Function to read audio data from a .wav file
def read_wave_file(file_path):
    with wave.open(file_path, 'rb') as wf:
        params = wf.getparams()
        frames = wf.readframes(params.nframes)
        return params, frames

# Function to write audio data to a .wav file
def write_wave_file(file_path, params, frames):
    with wave.open(file_path, 'wb') as wf:
        wf.setparams(params)
        wf.writeframes(frames)

# Function to convert audio frames to numpy array
def frames_to_array(frames, params):
    num_channels = params.nchannels
    sample_width = params.sampwidth
    dtype = 'int16' if sample_width == 2 else 'int32'  # Assuming 2 or 4 bytes per sample
    
    audio_data = struct.unpack('<' + str(len(frames) // sample_width) + 'h', frames)
    return np.array(audio_data, dtype=dtype), params.framerate, num_channels

# Function to convert numpy array to audio frames
def array_to_frames(audio_data, params):
    num_channels = params.nchannels
    sample_width = params.sampwidth
    dtype = 'int16' if sample_width == 2 else 'int32'  # Assuming 2 or 4 bytes per sample
    
    return struct.pack('<' + str(len(audio_data)) + 'h', *audio_data)

# Function to play audio data
def play_audio(audio_data, frame_rate):
    sd.play(audio_data, samplerate=frame_rate)
    sd.wait()

# Example usage
input_file = 'input.wav'
blowfish_key = b'secretkey'  # Blowfish key (must be between 4 and 56 bytes)

# Read the audio file
params, frames = read_wave_file(input_file)

# Convert frames to numpy array
audio_data, frame_rate, num_channels = frames_to_array(frames, params)

print("="*50)
print("BOB AND ALICE SECURE COMMUNICATION")
print("="*50)

print("Bob wants to send the original audio to Alice in a secure way.")
print()

# Play the original audio
print("Playing original audio...")
play_audio(audio_data, frame_rate)
print("[INFO] Original audio played.")
print()

print("="*50)
print("ENCRYPTION WITH BLOWFISH OFB MODE")
print("="*50)

print("Bob decides to encrypt the audio with the BlowFish algorithm.")
print(f"Bob chooses a secure key: {blowfish_key.decode()}")
print()

# Encrypt the audio data
blowfish = BlowFish(blowfish_key)
iv = urandom(8)  # Initialization vector
print(f"Bob uses BlowFish with OFB mode and generates a random initialization vector: {iv}")
data_encrypted = b''.join(blowfish.encrypt_ofb(audio_data.tobytes(), iv))
print("[INFO] Audio encryption complete.")
print()

# Convert encrypted bytes to numpy array for playback
# Note: This will sound like noise or garbage
audio_data_encrypted = np.frombuffer(data_encrypted, dtype=np.int16)

# Play the encrypted audio (this will be noise or garbage)
print("Playing encrypted audio...")
play_audio(audio_data_encrypted, frame_rate)
print("[INFO] Encrypted audio played.")
print()

print("="*50)
print("SIGNING WITH RABIN SIGNATURE")
print("="*50)

print("Now Bob decides to sign the message using the Rabin Signature Scheme.")
# RABIN
private_rabin_p, private_rabin_q = RabinSignature.generate_keys()
print(f"Bob generates two private keys:\n  p: {private_rabin_p}\n  q: {private_rabin_q}")
public_rabin_key = private_rabin_p * private_rabin_q
print(f"With the private keys, Bob generates a public key:\n  public key = {public_rabin_key} = p * q")
print()

rabin_sign, padding = RabinSignature.sign_rabin(private_rabin_p, private_rabin_q, audio_data_encrypted.tobytes())
print(f"Bob signs the audio message with the following signature:\n  Signature: {rabin_sign}\n  Padding: {padding}")
print()

print("="*50)
print("ENCRYPTING BLOWFISH KEY AND IV WITH EC-ELGAMAL")
print("="*50)

# Bob encrypts the Blowfish key and IV using Alice's EC-ElGamal public key
bob_ec = ECElGamal()
alice_ec = ECElGamal()  # Assuming Alice's public key is known to Bob

# Encrypt Blowfish key
ephemeral_public_key_key, encrypted_blowfish_key = bob_ec.encrypt(alice_ec.public_key, blowfish_key)
print(f"Bob encrypts the Blowfish key with Alice's EC-ElGamal public key.")
print(f"Encrypted Blowfish key: {encrypted_blowfish_key}")
print()

# Encrypt IV
ephemeral_public_key_iv, encrypted_iv = bob_ec.encrypt(alice_ec.public_key, iv)
print(f"Bob encrypts the IV with Alice's EC-ElGamal public key.")
print(f"Encrypted IV: {encrypted_iv}")
print()

print("="*50)
print("ALICE RECEIVES THE MESSAGE")
print("="*50)

# Alice decrypts the Blowfish key and IV using her private key
decrypted_blowfish_key = alice_ec.decrypt(alice_ec.private_key, ephemeral_public_key_key, encrypted_blowfish_key)
decrypted_iv = alice_ec.decrypt(alice_ec.private_key, ephemeral_public_key_iv, encrypted_iv)

print(f"Alice decrypts the Blowfish key: {decrypted_blowfish_key}")
print(f"Alice decrypts the IV: {decrypted_iv}")
print()

if RabinSignature.verify(public_rabin_key, audio_data_encrypted.tobytes(), rabin_sign, padding):
    print("Valid signature! The sender is authorized.")
    print()

    # Decrypt the audio data
    alice_blowfish = BlowFish(decrypted_blowfish_key)
    data_decrypted = b''.join(alice_blowfish.decrypt_ofb(data_encrypted, decrypted_iv))

    # Convert decrypted bytes back to numpy array
    audio_data_decrypted = np.frombuffer(data_decrypted, dtype=np.int16)

    # Play the decrypted audio
    print("Playing decrypted audio...")
    play_audio(audio_data_decrypted, frame_rate)
    print("[INFO] Decrypted audio played.")
else:
    print("Invalid signature! The sender is not authorized.")

print("="*50)
print("END OF SECURE COMMUNICATION")
print("="*50)