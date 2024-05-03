import json
from typing import Any
from packages.crypto.src import PublicKey
from providers import fetch_json
from .connection import Connection
from .account import Account

class AccountCreator:
    async def create_account(self, new_account_id: str, public_key: PublicKey) -> None:
        raise NotImplementedError()

class LocalAccountCreator(AccountCreator):
    def __init__(self, master_account: Account, initial_balance: int):
        super().__init__()
        self.master_account = master_account
        self.initial_balance = initial_balance

    async def create_account(self, new_account_id: str, public_key: PublicKey) -> None:
        await self.master_account.create_account(new_account_id, public_key, self.initial_balance)

class UrlAccountCreator(AccountCreator):
    def __init__(self, connection: Connection, helper_url: str):
        super().__init__()
        self.connection = connection
        self.helper_url = helper_url

    async def create_account(self, new_account_id: str, public_key: PublicKey) -> None:
        await fetch_json(
            f"{self.helper_url}/account",
            json.dumps({"newAccountId": new_account_id, "newAccountPublicKey": str(public_key)})
        )