import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_nonce(nonce_prefix, counter):
    # The nonce needs 8 bytes for the prefix and 4 for the counter
    if len(nonce_prefix) != 8:
        raise ValueError('Prefix must be 8 bytes')

    if counter < 0 or counter >= 2**32:
        raise ValueError('Counter is outside range')

    return nonce_prefix + counter.to_bytes(4, 'big')


def make_aad(meter_id, command, counter):
    # This information is checked when the message is decrypted
    if '|' in meter_id or '|' in command:
        raise ValueError('Invalid meter ID or command')

    if counter < 0 or counter >= 2**32:
        raise ValueError('Invalid counter')

    return meter_id.encode() + b'-' + command.encode() + b'-' + counter.to_bytes(4, 'big')


def encrypt_reading(secret_key, nonce_prefix, counter, meter_id, command, reading):
    nonce = make_nonce(nonce_prefix, counter)
    aad = make_aad(meter_id, command, counter)

    aes = AESGCM(secret_key)
    encrypted_reading = aes.encrypt(nonce, reading, aad)
    return nonce, encrypted_reading


def decrypt_reading(secret_key, nonce, counter, meter_id, command, encrypted_reading):
    aad = make_aad(meter_id, command, counter)

    aes = AESGCM(secret_key)
    reading = aes.decrypt(nonce, encrypted_reading, aad)
    return reading


class ReplayGuard:

    def __init__(self):
        self.last_counter = -1

    def receive(self, secret_key, nonce, counter, meter_id, command, encrypted_reading):
        # Check counter agrees with nonce
        if nonce != make_nonce(nonce[:8], counter):
            raise ValueError('Nonce and counter do not match')

        # Decrypt before checking the counter.
        reading = decrypt_reading(
            secret_key, nonce, counter, meter_id, command, encrypted_reading
        )

        if counter <= self.last_counter:
            raise ValueError('Replay detected')

        self.last_counter = counter
        return reading


def make_test_messages(use_flawed=False):
    # New key and prefix each run
    secret_key = os.urandom(16)
    nonce_prefix = os.urandom(8)

    reading1 = b'Electricity: 10 kWh'
    reading2 = b'Electricity: 20 kWh'
    meter_id = '000001'
    command = 'READING'

    counter1 = 0

    if use_flawed:
        counter2 = 0  # Repeats the first nonce exactly.
    else:
        counter2 = 1

    nonce1, encrypted1 = encrypt_reading(
        secret_key, nonce_prefix, counter1, meter_id, command, reading1
    )
    nonce2, encrypted2 = encrypt_reading(
        secret_key, nonce_prefix, counter2, meter_id, command, reading2
    )

    return reading1, reading2, nonce1, nonce2, encrypted1, encrypted2


def main():
    reading1, reading2, nonce1, nonce2, encrypted1, encrypted2 = make_test_messages()

    print('CORRECT AES-GCM USAGE')
    print('Message 1:', reading1.decode())
    print('Message 2:', reading2.decode())
    print('Nonce 1:', nonce1.hex())
    print('Nonce 2:', nonce2.hex())
    print('Nonce reused:', nonce1 == nonce2)


if __name__ == '__main__':
    main()
