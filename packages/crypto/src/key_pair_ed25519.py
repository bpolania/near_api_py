from utils import base_encode, base_decode # these are from '@near-js/utils'
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from .constants import KeySize, KeyType
from .key_pair_base import KeyPairBase, Signature
from .public_key import PublicKey

class KeyPairEd25519(KeyPairBase):
    def __init__(self, extended_secret_key: str):
        super().__init__()
        decoded = base_decode(extended_secret_key)
        secret_key = decoded[:KeySize.SECRET_KEY]
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.public_key = PublicKey(key_type=KeyType.ED25519, data=public_key)
        self.secret_key = base_encode(secret_key)
        self.extended_secret_key = extended_secret_key

    @staticmethod
    def from_random() -> 'KeyPairEd25519':
        private_key = ed25519.Ed25519PrivateKey.generate()
        secret_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        extended_secret_key = base_encode(secret_key + public_key)
        return KeyPairEd25519(extended_secret_key)

    def sign(self, message: bytes) -> Signature:
        secret_key = base_decode(self.secret_key)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
        signature = private_key.sign(message)
        return Signature(signature, self.public_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.public_key.verify(message, signature)

    def to_string(self) -> str:
        return f'ed25519:{self.extended_secret_key}'

    def get_public_key(self) -> PublicKey:
        return self.public_key