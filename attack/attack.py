import argparse
import sys
import time
from src.protocol import make_test_messages


def xor_bytes(first_bytes, second_bytes):
    answer = bytearray()

    for first, second in zip(first_bytes, second_bytes):
        answer.append(first ^ second)

    return bytes(answer)


def recover_reading(known_reading, encrypted1, encrypted2):
    # The last 16 bytes are the authentication tags, not the ciphertext.
    ciphertext1 = encrypted1[:-16]
    ciphertext2 = encrypted2[:-16]

    if len(known_reading) != len(ciphertext1) or len(ciphertext1) != len(ciphertext2):
        raise ValueError('This example needs messages of the same length')

    # Find the keystream from the reading I already know.
    keystream = xor_bytes(known_reading, ciphertext1)

    # Try using that keystream on the second encrypted reading.
    recovered_reading = xor_bytes(keystream, ciphertext2)
    return recovered_reading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['flawed', 'correct'], required=True)
    options = parser.parse_args()

    use_flawed = options.mode == 'flawed'
    reading1, reading2, nonce1, nonce2, encrypted1, encrypted2 = make_test_messages(use_flawed)

    start_time = time.perf_counter()
    recovered_reading = recover_reading(reading1, encrypted1, encrypted2)
    time_taken = (time.perf_counter() - start_time) * 1000

    attack_worked = recovered_reading == reading2

    print('Mode:', options.mode)
    print('Nonce reused:', nonce1 == nonce2)
    print('Recovered:', recovered_reading.decode('utf-8', errors='replace'))
    print('Expected:', reading2.decode())
    print('Attack successful:', attack_worked)
    print(f'XOR recovery time: {time_taken:.4f} ms')

    if attack_worked:
        return 0
    else:
        return 1


if __name__ == '__main__':
    sys.exit(main())
