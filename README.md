## Tested Environment
- Python 3.14.4
- Windows 11 Pro


## Structure
    README.md - this file
    requirememnts.txt - pinned dependencies
    src/protocol.py - correct implementation
    src/flawed.py - flawed build with overridden method
    attack/attack.py - attack with exit 0 = success, 1 = failed
    tests/test.py - unittests file

## Installation (Windows Powershell)

python -m venv .venv
python -m pip install -r requirements.txt

## Correct protocol run
python -m src.protocol

## Flaawed run
python -m src.flawed

## Tests run
python -m tests.test

## Attack demonstration
python -m attack.attack --mode flawed
python -m attack.attack --mode corect

## Expected output

- Mode Flawed:
    Nonce reuse - True
    Recovered Electricity - 20 kWh
    Attack successful - True

- Mode Correct:
    Nonce reuse - False
    Recovered - Not comprehendable
    Attack successful - False

## Reference
Authenticated encryption—Cryptography 51.0.0-dev1 documentation. (n.d.). Retrieved November 22, 2026, from https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
