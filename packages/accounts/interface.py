from typing import Any, Callable, Optional
from types import BlockReference

from .connection import Connection

class IntoConnection:
    def get_connection(self) -> Connection:
        raise NotImplementedError()

class FunctionCallOptions:
    def __init__(
        self,
        contract_id: str,
        method_name: str,
        args: Optional[dict] = None,
        gas: Optional[int] = None,
        attached_deposit: Optional[int] = None,
        stringify: Optional[Callable[[Any], bytes]] = None,
        js_contract: Optional[bool] = None,
    ):
        self.contract_id = contract_id
        self.method_name = method_name
        self.args = args
        self.gas = gas
        self.attached_deposit = attached_deposit
        self.stringify = stringify
        self.js_contract = js_contract

class ChangeFunctionCallOptions(FunctionCallOptions):
    def __init__(
        self,
        contract_id: str,
        method_name: str,
        args: Optional[dict] = None,
        gas: Optional[int] = None,
        attached_deposit: Optional[int] = None,
        stringify: Optional[Callable[[Any], bytes]] = None,
        js_contract: Optional[bool] = None,
        wallet_meta: Optional[str] = None,
        wallet_callback_url: Optional[str] = None,
    ):
        super().__init__(contract_id, method_name, args, gas, attached_deposit, stringify, js_contract)
        self.wallet_meta = wallet_meta
        self.wallet_callback_url = wallet_callback_url

class ViewFunctionCallOptions(FunctionCallOptions):
    def __init__(
        self,
        contract_id: str,
        method_name: str,
        args: Optional[dict] = None,
        gas: Optional[int] = None,
        attached_deposit: Optional[int] = None,
        stringify: Optional[Callable[[Any], bytes]] = None,
        js_contract: Optional[bool] = None,
        parse: Optional[Callable[[bytes], Any]] = None,
        block_query: Optional[BlockReference] = None,
    ):
        super().__init__(contract_id, method_name, args, gas, attached_deposit, stringify, js_contract)
        self.parse = parse
        self.block_query = block_query