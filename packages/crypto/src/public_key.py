from typing import Union
from types import Assignable
from utils import base_encode, base_decode
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class KeyType:
    ED25519 = 0

def key_type_to_str(key_type: KeyType) -> str:
    if key_type == KeyType.ED25519:
        return 'ed25519'
    else:
        raise ValueError(f'Unknown key type {key_type}')

def str_to_key_type(key_type: str) -> KeyType:
    key_type = key_type.lower()
    if key_type == 'ed25519':
        return KeyType.ED25519
    else:
        raise ValueError(f'Unknown key type {key_type}')

class PublicKey(Assignable):
    def __init__(self, key_type: KeyType, data: bytes):
        self.key_type = key_type
        self.data = data

    @classmethod
    def from_value(cls, value: Union[str, 'PublicKey']) -> 'PublicKey':
        if isinstance(value, str):
            return cls.from_string(value)
        return value

    @classmethod
    def from_string(cls, encoded_key: str) -> 'PublicKey':
        parts = encoded_key.split(':')
        if len(parts) == 1:
            public_key = parts[0]
            key_type = KeyType.ED25519
        elif len(parts) == 2:
            public_key = parts[1]
            key_type = str_to_key_type(parts[0])
        else:
            raise ValueError('Invalid encoded key format, must be <curve>:<encoded key>')

        decoded_public_key = base_decode(public_key)
        if len(decoded_public_key) != 32:  # KeySize.SECRET_KEY
            raise ValueError(f'Invalid public key size ({len(decoded_public_key)}), must be 32')

        return cls(key_type, decoded_public_key)

    def to_string(self) -> str:
        return f'{key_type_to_str(self.key_type)}:{base_encode(self.data)}'

    def verify(self, message: bytes, signature: bytes) -> bool:
        if self.key_type == KeyType.ED25519:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(self.data)
                public_key.verify(signature, message)
                return True
            except InvalidSignature:
                return False
        else:
            raise ValueError(f'Unknown key type {self.key_type}')