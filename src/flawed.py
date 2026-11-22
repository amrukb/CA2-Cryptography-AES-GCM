from src.protocol import make_test_messages

def main():
    reading1, reading2, nonce1, nonce2, encrypted1, encrypted2 = make_test_messages(True)

    print('FLAWED AES-GCM')
    print('Message 1:', reading1.decode())
    print('Message 2:', reading2.decode())
    print('Nonce 1:', nonce1.hex())
    print('Nonce 2:', nonce2.hex())
    print('Nonce reused:', nonce1 == nonce2)


if __name__ == '__main__':
    main()
