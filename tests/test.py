import os
import unittest
from cryptography.exceptions import InvalidTag
from src.protocol import make_nonce, encrypt_reading, decrypt_reading, make_test_messages
from attack.attack import recover_reading

class TestSmartMeter(unittest.TestCase):

    def setUp(self):
        self.secret_key = os.urandom(16)
        self.nonce_prefix = os.urandom(8)
        self.meter_id = "000001"
        self.command = "READING"
        self.reading = b"Electricity: 10 kWh"

    def test_encryption(self):
        # Encrypt reading and check can be decrypted.
        nonce, encrypted_reading = encrypt_reading(
            self.secret_key, self.nonce_prefix, 0,
            self.meter_id, self.command, self.reading
        )

        decrypted_reading = decrypt_reading(
            self.secret_key, nonce, 0,
            self.meter_id, self.command, encrypted_reading
        )

        self.assertEqual(decrypted_reading, self.reading)

    def test_tampering(self):
        # Change one byte and check that decryption fails.
        nonce, encrypted_reading = encrypt_reading(
            self.secret_key, self.nonce_prefix, 0,
            self.meter_id, self.command, self.reading
        )

        changed_reading = bytearray(encrypted_reading)
        changed_reading[0] = changed_reading[0] ^ 1

        with self.assertRaises(InvalidTag):
            decrypt_reading(
                self.secret_key, nonce, 0,
                self.meter_id, self.command, bytes(changed_reading)
            )

    def test_wrong_meter(self):
        # The reading should not decrypt with a different meter ID.
        nonce, encrypted_reading = encrypt_reading(
            self.secret_key, self.nonce_prefix, 0,
            self.meter_id, self.command, self.reading
        )

        with self.assertRaises(InvalidTag):
            decrypt_reading(
                self.secret_key, nonce, 0,
                "METER-002", self.command, encrypted_reading
            )

    def test_nonce(self):
        # A higher counter should give a different nonce.
        nonce1 = make_nonce(self.nonce_prefix, 0)
        nonce2 = make_nonce(self.nonce_prefix, 1)

        self.assertNotEqual(nonce1, nonce2)

    def test_flawed_attack(self):
        # The attack should recover reading 2 when the nonce is reused.
        reading1, reading2, nonce1, nonce2, encrypted1, encrypted2 = make_test_messages(True)

        recovered_reading = recover_reading(reading1, encrypted1, encrypted2)

        self.assertEqual(nonce1, nonce2)
        self.assertEqual(recovered_reading, reading2)

    def test_correct_attack(self):
        # The same attack should not recover reading 2 with different nonces.
        reading1, reading2, nonce1, nonce2, encrypted1, encrypted2 = make_test_messages(False)

        recovered_reading = recover_reading(reading1, encrypted1, encrypted2)

        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(recovered_reading, reading2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
