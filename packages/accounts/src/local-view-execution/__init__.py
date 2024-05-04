from typing import Any, Dict, Optional
from types import BlockReference, ContractCodeView
from utils import print_tx_outcome_logs
from ..interface import FunctionCallOptions
from .storage import Storage
from .runtime import Runtime
from .types import ContractState
from ..utils import view_state
from ..interface import IntoConnection
import json

class ViewFunctionCallOptions(FunctionCallOptions):
    block_query: Optional[BlockReference] = None

class LocalViewExecution:
    def __init__(self, connection: IntoConnection):
        self.connection = connection.get_connection()
        self.storage = Storage()

    async def _fetch_contract_code(self, contract_id: str, block_query: BlockReference) -> str:
        result = await self.connection.provider.query(ContractCodeView, {
            "request_type": "view_code",
            "account_id": contract_id,
            **block_query
        })
        return result["code_base64"]

    async def _fetch_contract_state(self, contract_id: str, block_query: BlockReference) -> ContractState:
        return await view_state(self.connection, contract_id, "", block_query)

    async def _fetch(self, contract_id: str, block_query: BlockReference) -> Dict[str, Any]:
        block = await self.connection.provider.block(block_query)
        block_hash = block["header"]["hash"]
        block_height = block["header"]["height"]
        block_timestamp = block["header"]["timestamp"]
        contract_code = await self._fetch_contract_code(contract_id, block_query)
        contract_state = await self._fetch_contract_state(contract_id, block_query)
        return {
            "block_hash": block_hash,
            "block_height": block_height,
            "block_timestamp": block_timestamp,
            "contract_code": contract_code,
            "contract_state": contract_state
        }

    async def _load_or_fetch(self, contract_id: str, block_query: BlockReference) -> Dict[str, Any]:
        stored = self.storage.load(block_query)
        if stored:
            return stored
        fetched = await self._fetch(contract_id, block_query)
        block_hash = fetched.pop("block_hash")
        self.storage.save(block_hash, fetched)
        return fetched

    async def view_function(self, options: ViewFunctionCallOptions) -> Any:
        contract_id = options.contract_id
        method_name = options.method_name
        args = options.args or {}
        block_query = options.block_query or {"finality": "optimistic"}
        method_args = json.dumps(args)
        fetched = await self._load_or_fetch(contract_id, block_query)
        contract_code = fetched["contract_code"]
        contract_state = fetched["contract_state"]
        block_height = fetched["block_height"]
        block_timestamp = fetched["block_timestamp"]
        runtime = Runtime(contract_id, contract_code, contract_state, block_height, block_timestamp, method_args)
        result, logs = await runtime.execute(method_name)
        if logs:
            print_tx_outcome_logs({"contract_id": contract_id, "logs": logs})
        return json.loads(result.decode())

__all__ = [
    "ViewFunctionCallOptions",
    "LocalViewExecution"
]