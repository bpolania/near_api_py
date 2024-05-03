from typing import Any, List
from signers import Signer, InMemorySigner
from providers import Provider, JsonRpcProvider, FailoverRpcProvider
from interface import IntoConnection

def get_provider(config: Any) -> Provider:
    if config.get("type") is None:
        return config
    elif config["type"] == "JsonRpcProvider":
        return JsonRpcProvider(**config.get("args", {}))
    elif config["type"] == "FailoverRpcProvider":
        providers = [JsonRpcProvider(arg) for arg in config.get("args", [])]
        return FailoverRpcProvider(providers)
    else:
        raise ValueError(f"Unknown provider type {config['type']}")

def get_signer(config: Any) -> Signer:
    if config.get("type") is None:
        return config
    elif config["type"] == "InMemorySigner":
        return InMemorySigner(config["keyStore"])
    else:
        raise ValueError(f"Unknown signer type {config['type']}")

class Connection(IntoConnection):
    def __init__(self, network_id: str, provider: Provider, signer: Signer, pyvm_account_id: str):
        self.network_id = network_id
        self.provider = provider
        self.signer = signer
        self.pyvm_account_id = pyvm_account_id

    def get_connection(self) -> "Connection":
        return self

    @classmethod
    def from_config(cls, config: Any) -> "Connection":
        provider = get_provider(config["provider"])
        signer = get_signer(config["signer"])
        return cls(config["networkId"], provider, signer, config["pyvmAccountId"])