from abc import ABC
from .key_pair_base import KeyPairBase
from .key_pair_ed25519 import KeyPairEd25519

class KeyPair(KeyPairBase, ABC):
    @staticmethod
    def from_random(curve: str) -> 'KeyPair':
        curve = curve.upper()
        if curve == 'ED25519':
            return KeyPairEd25519.from_random()
        else:
            raise ValueError(f'Unknown curve {curve}')

    @staticmethod
    def from_string(encoded_key: str) -> 'KeyPair':
        parts = encoded_key.split(':')
        if len(parts) == 1:
            return KeyPairEd25519(parts[0])
        elif len(parts) == 2:
            curve = parts[0].upper()
            if curve == 'ED25519':
                return KeyPairEd25519(parts[1])
            else:
                raise ValueError(f'Unknown curve: {parts[0]}')
        else:
            raise ValueError('Invalid encoded key format, must be <curve>:<encoded key>')