import asyncio
import json
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass
from packages.crypto.src import PublicKey
from providers import exponential_backoff
from transactions import (
    ActionCreators,
    Action,
    build_delegate_action,
    sign_delegate_action,
    sign_transaction,
    SignedDelegate,
    SignedTransaction,
    stringify_json_or_bytes,
)
from types import (
    PositionalArgsError,
    FinalExecutionOutcome,
    TypedError,
    ErrorContext,
    AccountView,
    AccessKeyView,
    AccessKeyViewRaw,
    AccessKeyList,
    AccessKeyInfoView,
    FunctionCallPermissionView,
    BlockReference,
)
from utils import (
    base_decode,
    base_encode,
    Logger,
    parse_result_error,
    DEFAULT_FUNCTION_CALL_GAS,
    print_tx_outcome_logs_and_failures,
)
from connection import Connection
from utils import view_function, view_state
from interface import ChangeFunctionCallOptions, IntoConnection, ViewFunctionCallOptions

# Default number of retries with different nonce before giving up on a transaction.
TX_NONCE_RETRY_NUMBER = 12

# Default wait until next retry in millis.
TX_NONCE_RETRY_WAIT = 500

# Exponential back off for waiting to retry.
TX_NONCE_RETRY_WAIT_BACKOFF = 1.5

@dataclass
class AccountBalance:
    total: str
    stateStaked: str
    staked: str
    available: str

@dataclass
class AccountAuthorizedApp:
    contractId: str
    amount: str
    publicKey: str

@dataclass
class SignAndSendTransactionOptions:
    receiverId: str
    actions: List[Action]
    walletMeta: Optional[str] = None
    walletCallbackUrl: Optional[str] = None
    returnError: Optional[bool] = None

@dataclass
class StakedBalance:
    validatorId: str
    amount: Optional[str] = None
    error: Optional[str] = None

@dataclass
class ActiveDelegatedStakeBalance:
    stakedValidators: List[StakedBalance]
    failedValidators: List[StakedBalance]
    total: Union[int, str]

@dataclass
class SignedDelegateOptions:
    actions: List[Action]
    blockHeightTtl: int
    receiverId: str

class Account(IntoConnection):
    def __init__(self, connection: Connection, account_id: str):
        self.connection = connection
        self.account_id = account_id
        self.access_key_by_public_key_cache: Dict[str, AccessKeyView] = {}

    def get_connection(self) -> Connection:
        return self.connection

    async def state(self) -> AccountView:
        return await self.connection.provider.query(
            {
                "request_type": "view_account",
                "account_id": self.account_id,
                "finality": "optimistic",
            }
        )

    async def sign_transaction(self, receiver_id: str, actions: List[Action]) -> Tuple[bytes, SignedTransaction]:
        access_key_info = await self.find_access_key(receiver_id, actions)
        if not access_key_info:
            raise TypedError(
                f"Can not sign transactions for account {self.account_id} on network {self.connection.network_id}, no matching key pair exists for this account",
                "KeyNotFound",
            )
        access_key = access_key_info["access_key"]

        block = await self.connection.provider.block({"finality": "final"})
        block_hash = block["header"]["hash"]

        nonce = access_key["nonce"] + 1
        return await sign_transaction(
            receiver_id,
            nonce,
            actions,
            base_decode(block_hash),
            self.connection.signer,
            self.account_id,
            self.connection.network_id,
        )

    async def sign_and_send_transaction(self, options: SignAndSendTransactionOptions) -> FinalExecutionOutcome:
        receiver_id = options["receiver_id"]
        actions = options["actions"]
        return_error = options.get("return_error", False)

        tx_hash, signed_tx = None, None
        result = await exponential_backoff(
            TX_NONCE_RETRY_WAIT,
            TX_NONCE_RETRY_NUMBER,
            TX_NONCE_RETRY_WAIT_BACKOFF,
            self._sign_and_send_transaction_async,
            receiver_id,
            actions,
        )

        if not result:
            raise TypedError(
                "nonce retries exceeded for transaction. This usually means there are too many parallel requests with the same access key.",
                "RetriesExceeded",
            )

        print_tx_outcome_logs_and_failures(
            {"contract_id": signed_tx["transaction"]["receiver_id"], "outcome": result}
        )

        if not return_error and isinstance(result["status"], dict) and "Failure" in result["status"]:
            failure = result["status"]["Failure"]
            if "error_message" in failure and "error_type" in failure:
                raise TypedError(
                    f'Transaction {result["transaction_outcome"]["id"]} failed. {failure["error_message"]}',
                    failure["error_type"],
                )
            else:
                raise parse_result_error(result)

        return result

    async def _sign_and_send_transaction_async(self, receiver_id: str, actions: List[Action]) -> Optional[FinalExecutionOutcome]:
        tx_hash, signed_tx = await self.sign_transaction(receiver_id, actions)
        public_key = signed_tx["transaction"]["public_key"]

        try:
            return await self.connection.provider.send_transaction(signed_tx)
        except Exception as e:
            if e.type == "InvalidNonce":
                Logger.warn(f'Retrying transaction {receiver_id}:{base_encode(tx_hash)} with new nonce.')
                del self.access_key_by_public_key_cache[str(public_key)]
                return None
            if e.type == "Expired":
                Logger.warn(f'Retrying transaction {receiver_id}:{base_encode(tx_hash)} due to expired block hash')
                return None

            e.context = ErrorContext(base_encode(tx_hash))
            raise e

    async def find_access_key(self, receiver_id: str, actions: List[Action]) -> Optional[Dict[str, Union[PublicKey, AccessKeyView]]]:
        public_key = await self.connection.signer.get_public_key(self.account_id, self.connection.network_id)
        if not public_key:
            raise TypedError(f"no matching key pair found in {self.connection.signer}", "PublicKeyNotFound")

        cached_access_key = self.access_key_by_public_key_cache.get(str(public_key))
        if cached_access_key is not None:
            return {"public_key": public_key, "access_key": cached_access_key}

        try:
            raw_access_key = await self.connection.provider.query(
                {
                    "request_type": "view_access_key",
                    "account_id": self.account_id,
                    "public_key": str(public_key),
                    "finality": "optimistic",
                }
            )

            access_key = {**raw_access_key, "nonce": int(raw_access_key.get("nonce", 0))}
            if str(public_key) in self.access_key_by_public_key_cache:
                return {"public_key": public_key, "access_key": self.access_key_by_public_key_cache[str(public_key)]}

            self.access_key_by_public_key_cache[str(public_key)] = access_key
            return {"public_key": public_key, "access_key": access_key}
        except Exception as e:
            if e.type == "AccessKeyDoesNotExist":
                return None

            raise e

    async def create_and_deploy_contract(self, contract_id: str, public_key: Union[str, PublicKey], data: bytes, amount: int) -> "Account":
        access_key = ActionCreators.full_access_key()
        await self.sign_and_send_transaction(
            {
                "receiver_id": contract_id,
                "actions": [
                    ActionCreators.create_account(),
                    ActionCreators.transfer(amount),
                    ActionCreators.add_key(PublicKey.from_string(public_key), access_key),
                    ActionCreators.deploy_contract(data),
                ],
            }
        )
        contract_account = Account(self.connection, contract_id)
        return contract_account

    async def send_money(self, receiver_id: str, amount: int) -> FinalExecutionOutcome:
        return await self.sign_and_send_transaction(
            {"receiver_id": receiver_id, "actions": [ActionCreators.transfer(amount)]}
        )

    async def create_account(self, new_account_id: str, public_key: Union[str, PublicKey], amount: int) -> FinalExecutionOutcome:
        access_key = ActionCreators.full_access_key()
        return await self.sign_and_send_transaction(
            {
                "receiver_id": new_account_id,
                "actions": [
                    ActionCreators.create_account(),
                    ActionCreators.transfer(amount),
                    ActionCreators.add_key(PublicKey.from_string(public_key), access_key),
                ],
            }
        )

    async def delete_account(self, beneficiary_id: str) -> None:
        Logger.log("Deleting an account does not automatically transfer NFTs and FTs to the beneficiary address. Ensure to transfer assets before deleting.")
        return await self.sign_and_send_transaction(
            {"receiver_id": self.account_id, "actions": [ActionCreators.delete_account(beneficiary_id)]}
        )

    async def deploy_contract(self, data: bytes) -> FinalExecutionOutcome:
        return await self.sign_and_send_transaction(
            {"receiver_id": self.account_id, "actions": [ActionCreators.deploy_contract(data)]}
        )

    def _encode_python_contract_args(self, contract_id: str, method: str, args: Any) -> bytes:
        return b"".join([contract_id.encode(), b"\0", method.encode(), b"\0", args.encode()])

    async def function_call(self, options: ChangeFunctionCallOptions) -> FinalExecutionOutcome:
        contract_id = options["contract_id"]
        method_name = options["method_name"]
        args = options.get("args", {})
        gas = options.get("gas", DEFAULT_FUNCTION_CALL_GAS)
        attached_deposit = options.get("attached_deposit")
        wallet_meta = options.get("wallet_meta")
        wallet_callback_url = options.get("wallet_callback_url")
        stringify_arg = options.get("stringify", stringify_json_or_bytes)
        python_contract = options.get("python_contract", False)

        self._validate_args(args)
        function_call_args = None

        if python_contract:
            encoded_args = self._encode_python_contract_args(contract_id, method_name, json.dumps(args))
            function_call_args = ["call_python_contract", encoded_args, gas, attached_deposit, None, True]
        else:
            function_call_args = [method_name, args, gas, attached_deposit, stringify_arg, False]

        return await self.sign_and_send_transaction(
            {
                "receiver_id": self.connection.pyvm_account_id if python_contract else contract_id,
                "actions": [ActionCreators.function_call(*function_call_args)],
                "wallet_meta": wallet_meta,
                "wallet_callback_url": wallet_callback_url,
            }
        )

    async def add_key(self, public_key: Union[str, PublicKey], contract_id: Optional[str] = None, method_names: Optional[Union[str, List[str]]] = None, amount: Optional[int] = None) -> FinalExecutionOutcome:
        if not method_names:
            method_names = []
        if not isinstance(method_names, list):
            method_names = [method_names]

        access_key = ActionCreators.full_access_key() if not contract_id else ActionCreators.function_call_access_key(contract_id, method_names, amount)
        return await self.sign_and_send_transaction(
            {
                "receiver_id": self.account_id,
                "actions": [ActionCreators.add_key(PublicKey.from_string(public_key), access_key)],
            }
        )

    async def delete_key(self, public_key: Union[str, PublicKey]) -> FinalExecutionOutcome:
        return await self.sign_and_send_transaction(
            {
                "receiver_id": self.account_id,
                "actions": [ActionCreators.delete_key(PublicKey.from_string(public_key))],
            }
        )

    async def stake(self, public_key: Union[str, PublicKey], amount: int) -> FinalExecutionOutcome:
        return await self.sign_and_send_transaction(
            {
                "receiver_id": self.account_id,
                "actions": [ActionCreators.stake(amount, PublicKey.from_string(public_key))],
            }
        )

    async def signed_delegate(self, options: SignedDelegateOptions) -> SignedDelegate:
        actions = options["actions"]
        block_height_ttl = options["block_height_ttl"]
        receiver_id = options["receiver_id"]

        provider, signer = self.connection.provider, self.connection.signer
        block = await provider.block({"finality": "final"})
        header = block["header"]
        access_key_info = await self.find_access_key(None, None)
        access_key, public_key = access_key_info["access_key"], access_key_info["public_key"]

        delegate_action = build_delegate_action(
            {
                "actions": actions,
                "max_block_height": int(header["height"]) + block_height_ttl,
                "nonce": int(access_key["nonce"]) + 1,
                "public_key": public_key,
                "receiver_id": receiver_id,
                "sender_id": self.account_id,
            }
        )

        signed_delegate_action = await sign_delegate_action(
            {
                "delegate_action": delegate_action,
                "signer": {
                    "sign": lambda message: signer.sign_message(message, delegate_action["sender_id"], self.connection.network_id)["signature"]
                },
            }
        )

        return signed_delegate_action["signed_delegate_action"]

    def _validate_args(self, args: Any) -> None:
        is_uint8_array = hasattr(args, "byteLength") and args.byteLength == len(args)
        if is_uint8_array:
            return

        if isinstance(args, list) or not isinstance(args, dict):
            raise PositionalArgsError()

    async def view_function(self, options: ViewFunctionCallOptions) -> Any:
        return await view_function(self.connection, options)

    async def view_state(self, prefix: Union[str, bytes], block_query: BlockReference = {"finality": "optimistic"}) -> List[Dict[str, bytes]]:
        return await view_state(self.connection, self.account_id, prefix, block_query)

    async def get_access_keys(self) -> List[AccessKeyInfoView]:
        response = await self.connection.provider.query(
            {
                "request_type": "view_access_key_list",
                "account_id": self.account_id,
                "finality": "optimistic",
            }
        )
        return [
            {**key, "access_key": {**key["access_key"], "nonce": int(key["access_key"]["nonce"])}}
            for key in response.get("keys", [])
        ]

    async def get_account_details(self) -> Dict[str, List[AccountAuthorizedApp]]:
        access_keys = await self.get_access_keys()
        authorized_apps = [
            {
                "contract_id": perm["FunctionCall"]["receiver_id"],
                "amount": perm["FunctionCall"]["allowance"],
                "public_key": item["public_key"],
            }
            for item in access_keys
            if item["access_key"]["permission"] != "FullAccess"
            for perm in [item["access_key"]["permission"]]
        ]
        return {"authorized_apps": authorized_apps}

    async def get_account_balance(self) -> AccountBalance:
        protocol_config = await self.connection.provider.experimental_protocol_config({"finality": "final"})
        state = await self.state()

        cost_per_byte = int(protocol_config["runtime_config"]["storage_amount_per_byte"])
        state_staked = int(state["storage_usage"]) * cost_per_byte
        staked = int(state["locked"])
        total_balance = int(state["amount"]) + staked
        available_balance = total_balance - (staked if staked > state_staked else state_staked)

        return {
            "total": str(total_balance),
            "stateStaked": str(state_staked),
            "staked": str(staked),
            "available": str(available_balance),
        }

    async def get_active_delegated_stake_balance(self) -> ActiveDelegatedStakeBalance:
        block = await self.connection.provider.block({"finality": "final"})
        block_hash = block["header"]["hash"]
        epoch_id = block["header"]["epoch_id"]
        validators_info = await self.connection.provider.validators(epoch_id)
        current_validators = validators_info["current_validators"]
        next_validators = validators_info["next_validators"]
        current_proposals = validators_info["current_proposals"]

        pools = set(
            validator["account_id"]
            for validator in current_validators + next_validators + current_proposals
        )
        unique_pools = list(pools)

        promises = [
            self.view_function(
                {
                    "contract_id": validator,
                    "method_name": "get_account_total_balance",
                    "args": {"account_id": self.account_id},
                    "block_query": {"block_id": block_hash},
                }
            )
            for validator in unique_pools
        ]
        results = await asyncio.gather(*promises, return_exceptions=True)

        has_timeout_error = any(
            isinstance(result, Exception) and result.type == "TimeoutError"
            for result in results
        )
        if has_timeout_error:
            raise Exception("Failed to get delegated stake balance")

        summary = {
            "staked_validators": [],
            "failed_validators": [],
            "total": 0,
        }
        for index, state in enumerate(results):
            validator_id = unique_pools[index]
            if isinstance(state, int):
                if state != 0:
                    summary["staked_validators"].append({"validator_id": validator_id, "amount": str(state)})
                    summary["total"] += state
            elif isinstance(state, Exception):
                summary["failed_validators"].append({"validator_id": validator_id, "error": str(state)})

        return {
            **summary,
            "total": str(summary["total"]),
        }