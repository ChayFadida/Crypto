import wave
import struct
import numpy as np
import sounddevice as sd
from blowfish import Cipher
from os import urandom

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
key = b'secretkey'  # Blowfish key (must be between 4 and 56 bytes)

# Read the audio file
params, frames = read_wave_file(input_file)

# Convert frames to numpy array
audio_data, frame_rate, num_channels = frames_to_array(frames, params)

# Encrypt the audio data
cipher = Cipher(key)
iv = urandom(8)  # Initialization vector
data_encrypted = b''.join(cipher.encrypt_ofb(audio_data.tobytes(), iv))

# Convert encrypted bytes to numpy array for playback
# Note: This will sound like noise or garbage
audio_data_encrypted = np.frombuffer(data_encrypted, dtype=np.int16)

# Play the original audio
print("Playing original audio...")
play_audio(audio_data, frame_rate)

# Play the encrypted audio (this will be noise or garbage)
print("Playing encrypted audio...")
play_audio(audio_data_encrypted, frame_rate)

# Decrypt the audio data
data_decrypted = b''.join(cipher.decrypt_ofb(data_encrypted, iv))

# Convert decrypted bytes back to numpy array
audio_data_decrypted = np.frombuffer(data_decrypted, dtype=np.int16)

# Play the decrypted audio
print("Playing decrypted audio...")
play_audio(audio_data_decrypted, frame_rate)
