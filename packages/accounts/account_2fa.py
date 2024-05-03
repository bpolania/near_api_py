import base64
import json
from typing import Any, Callable, Optional

from crypto import PublicKey
from types import FinalExecutionOutcome, TypedError, FunctionCallPermissionView
from providers import fetch_json
from transactions import ActionCreators
from utils import Logger

from .account import SignAndSendTransactionOptions
from .account_multisig import AccountMultisig
from .connection import Connection
from .constants import MULTISIG_CHANGE_METHODS, MULTISIG_CONFIRM_METHODS, MULTISIG_DEPOSIT, MULTISIG_GAS
from .types import MultisigStateStatus

AddKey, DeleteKey, DeployContract, FullAccessKey, FunctionCall, FunctionCallAccessKey = ActionCreators()

SendCodeFunction = Callable[[], Any]
GetCodeFunction = Callable[[Any], str]
VerifyCodeFunction = Callable[[Any], Any]

class Account2FA(AccountMultisig):
    def __init__(self, connection: Connection, account_id: str, options: Any):
        super().__init__(connection, account_id, options)
        self.helper_url = options.get("helperUrl", "https://helper.testnet.near.org")
        self.storage = options.get("storage")
        self.send_code = options.get("sendCode", self.send_code_default)
        self.get_code = options.get("getCode", self.get_code_default)
        self.verify_code = options.get("verifyCode", self.verify_code_default)
        self.on_confirm_result = options.get("onConfirmResult")

    async def sign_and_send_transaction(self, options: SignAndSendTransactionOptions) -> FinalExecutionOutcome:
        await super().sign_and_send_transaction(options)
        await self.send_code()
        result = await self.prompt_and_verify()
        if self.on_confirm_result:
            await self.on_confirm_result(result)
        return result

    async def deploy_multisig(self, contract_bytes: bytes) -> FinalExecutionOutcome:
        account_id = self.account_id

        recovery_methods = await self.get_recovery_methods()
        seed_or_ledger_key = [
            rm["publicKey"]
            for rm in recovery_methods["data"]
            if (rm["kind"] == "phrase" or rm["kind"] == "ledger") and rm["publicKey"] is not None
        ]

        access_keys = await self.get_access_keys()
        fak2lak = [
            PublicKey.from_string(ak["public_key"])
            for ak in access_keys
            if ak["access_key"]["permission"] == "FullAccess" and ak["public_key"] not in seed_or_ledger_key
        ]

        confirm_only_key = PublicKey.from_string((await self.post_signed_json("/2fa/getAccessKey", {"accountId": account_id}))["publicKey"])

        new_args = bytes(json.dumps({"num_confirmations": 2}), "utf-8")

        actions = [
            *[DeleteKey(pk) for pk in fak2lak],
            *[AddKey(pk, FunctionCallAccessKey(account_id, MULTISIG_CHANGE_METHODS, None)) for pk in fak2lak],
            AddKey(confirm_only_key, FunctionCallAccessKey(account_id, MULTISIG_CONFIRM_METHODS, None)),
            DeployContract(contract_bytes),
        ]
        new_function_call_action_batch = actions + [FunctionCall("new", new_args, MULTISIG_GAS, MULTISIG_DEPOSIT)]
        Logger.log("deploying multisig contract for", account_id)

        multisig_state_status = (await self.check_multisig_code_and_state_status(contract_bytes))["stateStatus"]
        if multisig_state_status == MultisigStateStatus.STATE_NOT_INITIALIZED:
            return await super().sign_and_send_transaction_with_account(account_id, new_function_call_action_batch)
        elif multisig_state_status == MultisigStateStatus.VALID_STATE:
            return await super().sign_and_send_transaction_with_account(account_id, actions)
        elif multisig_state_status == MultisigStateStatus.INVALID_STATE:
            raise TypedError(
                f"Can not deploy a contract to account {self.account_id} on network {self.connection.network_id}, the account has existing state.",
                "ContractHasExistingState"
            )
        else:
            raise TypedError(
                f"Can not deploy a contract to account {self.account_id} on network {self.connection.network_id}, the account state could not be verified.",
                "ContractStateUnknown"
            )

    async def disable_with_fak(self, contract_bytes: bytes, cleanup_contract_bytes: Optional[bytes] = None) -> FinalExecutionOutcome:
        cleanup_actions = []
        if cleanup_contract_bytes:
            try:
                await self.delete_all_requests()
            except Exception as e:
                pass
            cleanup_actions = await self.get_2fa_disable_cleanup_actions(cleanup_contract_bytes)

        key_conversion_actions = await self.get_2fa_disable_key_conversion_actions()

        actions = [
            *cleanup_actions,
            *key_conversion_actions,
            DeployContract(contract_bytes)
        ]

        access_key_info = await self.find_access_key(self.account_id, actions)

        if access_key_info and access_key_info["access_key"] and access_key_info["access_key"]["permission"] != "FullAccess":
            raise TypedError("No full access key found in keystore. Unable to bypass multisig", "NoFAKFound")

        return await self.sign_and_send_transaction_with_account(self.account_id, actions)

    async def get_2fa_disable_cleanup_actions(self, cleanup_contract_bytes: bytes) -> list:
        try:
            current_account_state = await self.view_state("")
        except Exception as error:
            cause = error.__cause__ and error.__cause__.__class__.__name__
            if cause == "NO_CONTRACT_CODE":
                return []
            if cause == "TOO_LARGE_CONTRACT_STATE":
                raise TypedError(
                    f"Can not deploy a contract to account {self.account_id} on network {self.connection.network_id}, the account has existing state.",
                    "ContractHasExistingState"
                )
            raise error

        current_account_state_keys = [key.decode("base64") for key, _ in current_account_state]
        if current_account_state:
            return [
                DeployContract(cleanup_contract_bytes),
                FunctionCall("clean", {"keys": current_account_state_keys}, MULTISIG_GAS, 0)
            ]
        else:
            return []

    async def get_2fa_disable_key_conversion_actions(self) -> list:
        account_id = self.account_id
        access_keys = await self.get_access_keys()
        lak2fak = [
            ak
            for ak in access_keys
            if ak["access_key"]["permission"] != "FullAccess"
            and (
                isinstance(ak["access_key"]["permission"], dict)
                and ak["access_key"]["permission"].get("FunctionCall", {}).get("receiver_id") == account_id
                and len(ak["access_key"]["permission"]["FunctionCall"].get("method_names", [])) == 4
                and "add_request_and_confirm" in ak["access_key"]["permission"]["FunctionCall"]["method_names"]
            )
        ]
        confirm_only_key = PublicKey.from_string((await self.post_signed_json("/2fa/getAccessKey", {"accountId": account_id}))["publicKey"])
        return [
            DeleteKey(confirm_only_key),
            *[DeleteKey(PublicKey.from_string(ak["public_key"])) for ak in lak2fak],
            *[AddKey(PublicKey.from_string(ak["public_key"]), FullAccessKey()) for ak in lak2fak]
        ]

    async def disable(self, contract_bytes: bytes, cleanup_contract_bytes: bytes) -> FinalExecutionOutcome:
        state_status = (await self.check_multisig_code_and_state_status())["stateStatus"]
        if state_status != MultisigStateStatus.VALID_STATE and state_status != MultisigStateStatus.STATE_NOT_INITIALIZED:
            raise TypedError(
                f"Can not deploy a contract to account {self.account_id} on network {self.connection.network_id}, the account state could not be verified.",
                "ContractStateUnknown"
            )

        delete_all_requests_error = None
        try:
            await self.delete_all_requests()
        except Exception as e:
            delete_all_requests_error = e

        try:
            cleanup_actions = await self.get_2fa_disable_cleanup_actions(cleanup_contract_bytes)
        except Exception as e:
            if e.type == "ContractHasExistingState":
                raise delete_all_requests_error or e
            raise e

        actions = [
            *cleanup_actions,
            *(await self.get_2fa_disable_key_conversion_actions()),
            DeployContract(contract_bytes),
        ]
        Logger.log("disabling 2fa for", self.account_id)
        return await self.sign_and_send_transaction({"receiverId": self.account_id, "actions": actions})

    async def send_code_default(self) -> str:
        account_id = self.account_id
        request_id = self.get_request()["requestId"]
        method = await self.get_2fa_method()
        await self.post_signed_json("/2fa/send", {"accountId": account_id, "method": method, "requestId": request_id})
        return request_id

    async def get_code_default(self) -> str:
        raise Exception("There is no getCode callback provided. Please provide your own in AccountMultisig constructor options. It has a parameter method where method.kind is \"email\" or \"phone\".")

    async def prompt_and_verify(self) -> Any:
        method = await self.get_2fa_method()
        security_code = await self.get_code(method)
        try:
            result = await self.verify_code(security_code)
            return result
        except Exception as e:
            Logger.warn("Error validating security code:", e)
            if "invalid 2fa code provided" in str(e) or "2fa code not valid" in str(e):
                return await self.prompt_and_verify()
            raise e

    async def verify_code_default(self, security_code: str) -> Any:
        account_id = self.account_id
        request = self.get_request()
        if not request:
            raise Exception("no request pending")
        request_id = request["requestId"]
        return await self.post_signed_json("/2fa/verify", {"accountId": account_id, "securityCode": security_code, "requestId": request_id})

    async def get_recovery_methods(self) -> dict:
        account_id = self.account_id
        return {"accountId": account_id, "data": await self.post_signed_json("/account/recoveryMethods", {"accountId": account_id})}

    async def get_2fa_method(self) -> Optional[dict]:
        recovery_methods = await self.get_recovery_methods()
        data = recovery_methods["data"]
        if data:
            data = next((m for m in data if m["kind"].startswith("2fa-")), None)
        if not data:
            return None
        kind = data["kind"]
        detail = data["detail"]
        return {"kind": kind, "detail": detail}

    async def signature_for(self) -> dict:
        account_id = self.account_id
        block = await self.connection.provider.block({"finality": "final"})
        block_number = str(block["header"]["height"])
        signed = await self.connection.signer.sign_message(bytes(block_number, "utf-8"), account_id, self.connection.network_id)
        block_number_signature = base64.b64encode(signed["signature"]).decode("utf-8")
        return {"blockNumber": block_number, "blockNumberSignature": block_number_signature}

    async def post_signed_json(self, path: str, body: dict) -> Any:
        signature = await self.signature_for()
        return await fetch_json(self.helper_url + path, json.dumps({**body, **signature}))