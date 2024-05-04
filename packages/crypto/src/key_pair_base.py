from abc import ABC, abstractmethod
from .public_key import PublicKey

class Signature:
    def __init__(self, signature: bytes, public_key: PublicKey):
        self.signature = signature
        self.public_key = public_key

class KeyPairBase(ABC):
    @abstractmethod
    def sign(self, message: bytes) -> Signature:
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        pass

    @abstractmethod
    def to_string(self) -> str:
        pass

    @abstractmethod
    def get_public_key(self) -> PublicKey:
        pass