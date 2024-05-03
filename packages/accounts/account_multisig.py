import json
import asyncio
from enum import Enum
from typing import List, Dict, Any

from transactions import Action, ActionCreators
from types import FinalExecutionOutcome
from utils import Logger

from .account import Account, SignAndSendTransactionOptions
from .connection import Connection
from .constants import MULTISIG_ALLOWANCE, MULTISIG_CHANGE_METHODS, MULTISIG_DEPOSIT, MULTISIG_GAS, MULTISIG_STORAGE_KEY
from .types import MultisigDeleteRequestRejectionError, MultisigStateStatus

class MultisigCodeStatus(Enum):
    INVALID_CODE = 1
    VALID_CODE = 2
    UNKNOWN_CODE = 3

# in memory request cache for node w/o localStorage
storage_fallback = {
    MULTISIG_STORAGE_KEY: None
}

class AccountMultisig(Account):
    def __init__(self, connection: Connection, account_id: str, options: Dict[str, Any]):
        super().__init__(connection, account_id)
        self.storage = options.get("storage")
        self.on_add_request_result = options.get("onAddRequestResult")

    async def sign_and_send_transaction_with_account(self, receiver_id: str, actions: List[Action]) -> FinalExecutionOutcome:
        return await super().sign_and_send_transaction({"receiverId": receiver_id, "actions": actions})

    async def sign_and_send_transaction(self, options: SignAndSendTransactionOptions) -> FinalExecutionOutcome:
        account_id = self.account_id
        receiver_id = options["receiverId"]
        actions = options["actions"]

        args = json.dumps({
            "request": {
                "receiver_id": receiver_id,
                "actions": convert_actions(actions, account_id, receiver_id)
            }
        }).encode("utf-8")

        try:
            result = await super().sign_and_send_transaction({
                "receiverId": account_id,
                "actions": [ActionCreators.function_call("add_request_and_confirm", args, MULTISIG_GAS, MULTISIG_DEPOSIT)]
            })
        except Exception as e:
            if "Account has too many active requests. Confirm or delete some" in str(e):
                await self.delete_unconfirmed_requests()
                return await self.sign_and_send_transaction(options)
            raise e

        if not result.get("status"):
            raise Exception("Request failed")

        status = result["status"]
        if not status.get("SuccessValue") or not isinstance(status["SuccessValue"], str):
            raise Exception("Request failed")

        self.set_request({
            "accountId": account_id,
            "actions": actions,
            "requestId": int(status["SuccessValue"].encode("ascii"))
        })

        if self.on_add_request_result:
            await self.on_add_request_result(result)

        await self.delete_unconfirmed_requests()

        return result

    async def check_multisig_code_and_state_status(self, contract_bytes: bytes = None) -> Dict[str, Any]:
        u32_max = 4_294_967_295
        valid_code_status_if_no_deploy = MultisigCodeStatus.UNKNOWN_CODE if contract_bytes else MultisigCodeStatus.VALID_CODE

        try:
            if contract_bytes:
                await super().sign_and_send_transaction({
                    "receiverId": self.account_id,
                    "actions": [
                        ActionCreators.deploy_contract(contract_bytes),
                        ActionCreators.function_call("delete_request", {"request_id": u32_max}, MULTISIG_GAS, MULTISIG_DEPOSIT)
                    ]
                })
            else:
                await self.delete_request(u32_max)

            return {"codeStatus": MultisigCodeStatus.VALID_CODE, "stateStatus": MultisigStateStatus.VALID_STATE}
        except Exception as e:
            if MultisigDeleteRequestRejectionError.CANNOT_DESERIALIZE_STATE.search(str(e)):
                return {"codeStatus": valid_code_status_if_no_deploy, "stateStatus": MultisigStateStatus.INVALID_STATE}
            elif MultisigDeleteRequestRejectionError.MULTISIG_NOT_INITIALIZED.search(str(e)):
                return {"codeStatus": valid_code_status_if_no_deploy, "stateStatus": MultisigStateStatus.STATE_NOT_INITIALIZED}
            elif MultisigDeleteRequestRejectionError.NO_SUCH_REQUEST.search(str(e)):
                return {"codeStatus": valid_code_status_if_no_deploy, "stateStatus": MultisigStateStatus.VALID_STATE}
            elif MultisigDeleteRequestRejectionError.METHOD_NOT_FOUND.search(str(e)):
                return {"codeStatus": MultisigCodeStatus.INVALID_CODE, "stateStatus": MultisigStateStatus.UNKNOWN_STATE}
            raise e

    async def delete_request(self, request_id: int) -> FinalExecutionOutcome:
        return await super().sign_and_send_transaction({
            "receiverId": self.account_id,
            "actions": [ActionCreators.function_call("delete_request", {"request_id": request_id}, MULTISIG_GAS, MULTISIG_DEPOSIT)]
        })

    async def delete_all_requests(self) -> None:
        request_ids = await self.get_request_ids()
        if request_ids:
            await asyncio.gather(*[self.delete_request(request_id) for request_id in request_ids])

    async def delete_unconfirmed_requests(self) -> None:
        request_ids = await self.get_request_ids()
        current_request = self.get_request()

        for request_id in request_ids:
            if request_id == current_request.get("requestId"):
                continue

            try:
                await super().sign_and_send_transaction({
                    "receiverId": self.account_id,
                    "actions": [ActionCreators.function_call("delete_request", {"request_id": request_id}, MULTISIG_GAS, MULTISIG_DEPOSIT)]
                })
            except Exception as e:
                Logger.warn("Attempt to delete an earlier request before 15 minutes failed. Will try again.")

    async def get_request_ids(self) -> List[str]:
        return await self.view_function({
            "contractId": self.account_id,
            "methodName": "list_request_ids"
        })

    def get_request(self) -> Dict[str, Any]:
        if self.storage:
            return json.loads(self.storage.get(MULTISIG_STORAGE_KEY, "{}"))
        return storage_fallback[MULTISIG_STORAGE_KEY]

    def set_request(self, data: Dict[str, Any]) -> None:
        if self.storage:
            self.storage[MULTISIG_STORAGE_KEY] = json.dumps(data)
        else:
            storage_fallback[MULTISIG_STORAGE_KEY] = data

def convert_pk_for_contract(pk: str) -> str:
    return pk.replace("ed25519:", "")

def convert_actions(actions: List[Action], account_id: str, receiver_id: str) -> List[Dict[str, Any]]:
    converted_actions = []
    for action in actions:
        action_type = action["enum"]
        gas = action[action_type].get("gas")
        public_key = action[action_type].get("publicKey")
        method_name = action[action_type].get("methodName")
        args = action[action_type].get("args")
        deposit = action[action_type].get("deposit")
        access_key = action[action_type].get("accessKey")
        code = action[action_type].get("code")

        converted_action = {
            "type": action_type[0].upper() + action_type[1:],
            "gas": str(gas) if gas else None,
            "public_key": convert_pk_for_contract(public_key) if public_key else None,
            "method_name": method_name,
            "args": args.encode("base64").decode("utf-8") if args else None,
            "code": code.encode("base64").decode("utf-8") if code else None,
            "amount": str(deposit) if deposit else None,
            "deposit": str(deposit) if deposit else "0",
            "permission": None
        }

        if access_key:
            if receiver_id == account_id and access_key["permission"]["enum"] != "fullAccess":
                converted_action["permission"] = {
                    "receiver_id": account_id,
                    "allowance": str(MULTISIG_ALLOWANCE),
                    "method_names": MULTISIG_CHANGE_METHODS
                }

            if access_key["permission"]["enum"] == "functionCall":
                receiver_id = access_key["permission"]["functionCall"]["receiverId"]
                method_names = access_key["permission"]["functionCall"]["methodNames"]
                allowance = access_key["permission"]["functionCall"].get("allowance")
                converted_action["permission"] = {
                    "receiver_id": receiver_id,
                    "allowance": str(allowance) if allowance else None,
                    "method_names": method_names
                }

        converted_actions.append(converted_action)

    return converted_actions