import json
import base64
import asyncio
from typing import List, Dict, Any, Optional, Union, Callable

from utils import get_transaction_last_result, Logger
from types import ArgumentTypeError, PositionalArgsError
from .local_view_execution import LocalViewExecution
from .validators import is_my_json_valid
from .account import Account
from .errors import (
    UnsupportedSerializationError,
    UnknownArgumentError,
    ArgumentSchemaError,
    ConflictingOptions,
)
from .interface import IntoConnection
from .connection import Connection
from .utils import view_function

def name_function(name: str, body: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any) -> Any:
        return body(*args)

    wrapper.__name__ = name
    return wrapper

def validate_arguments(args: Dict[str, Any], abi_function: Dict[str, Any], abi_root: Dict[str, Any]) -> None:
    if not is_object(args):
        return

    if abi_function.get("params") and abi_function["params"]["serialization_type"] != "Json":
        raise UnsupportedSerializationError(abi_function["name"], abi_function["params"]["serialization_type"])

    if abi_function.get("result") and abi_function["result"]["serialization_type"] != "Json":
        raise UnsupportedSerializationError(abi_function["name"], abi_function["result"]["serialization_type"])

    params = abi_function.get("params", {}).get("args", [])
    for param in params:
        arg = args.get(param["name"])
        type_schema = param["type_schema"]
        type_schema["definitions"] = abi_root["body"]["root_schema"]["definitions"]
        validate = is_my_json_valid(type_schema)
        if not validate(arg):
            raise ArgumentSchemaError(param["name"], validate.errors)

    # Check there are no extra unknown arguments passed
    for arg_name in args.keys():
        if not any(param["name"] == arg_name for param in params):
            raise UnknownArgumentError(arg_name, [param["name"] for param in params])

def is_uint8array(x: Any) -> bool:
    return hasattr(x, "byteLength") and x.byteLength == len(x)

def is_object(x: Any) -> bool:
    return isinstance(x, dict)

class Contract:
    def __init__(self, connection: Union[IntoConnection, Account], contract_id: str, options: Dict[str, Any]):
        self.connection = connection.get_connection() if isinstance(connection, IntoConnection) else connection
        if isinstance(connection, Account):
            Logger.warning("Using Account instance in Contract constructor is deprecated. Use Connection instead.")
            self.account = connection
        else:
            self.account = None
        self.contract_id = contract_id
        self.lve = LocalViewExecution(connection)

        view_methods = options.get("viewMethods", [])
        change_methods = options.get("changeMethods", [])
        abi_root = options.get("abi")
        use_local_view_execution = options.get("useLocalViewExecution", False)

        view_methods_with_abi = [{"name": name, "abi": None} for name in view_methods]
        change_methods_with_abi = [{"name": name, "abi": None} for name in change_methods]

        if abi_root:
            if view_methods_with_abi or change_methods_with_abi:
                raise ConflictingOptions()
            view_methods_with_abi = [
                {"name": method["name"], "abi": method}
                for method in abi_root["body"]["functions"]
                if method["kind"] == "View"
            ]
            change_methods_with_abi = [
                {"name": method["name"], "abi": method}
                for method in abi_root["body"]["functions"]
                if method["kind"] == "Call"
            ]

        for method in view_methods_with_abi:
            setattr(self, method["name"], name_function(method["name"], self._create_view_method(method["name"], method["abi"], abi_root, use_local_view_execution)))

        for method in change_methods_with_abi:
            setattr(self, method["name"], name_function(method["name"], self._create_change_method(method["name"], method["abi"], abi_root)))

    def _create_view_method(self, method_name: str, abi: Optional[Dict[str, Any]], abi_root: Optional[Dict[str, Any]], use_local_view_execution: bool) -> Callable[..., Any]:
        async def view_method(args: Union[Dict[str, Any], bytes] = {}, options: Dict[str, Any] = {}) -> Any:
            if not (is_object(args) or is_uint8array(args)) or not is_object(options):
                raise PositionalArgsError()

            if abi:
                validate_arguments(args, abi, abi_root)

            if use_local_view_execution:
                try:
                    return await self.lve.view_function(contract_id=self.contract_id, method_name=method_name, args=args, **options)
                except Exception as e:
                    Logger.warning(f"Local view execution failed with: {str(e)}")
                    Logger.warning("Fallback to normal RPC call")

            if self.account:
                return await self.account.view_function(contract_id=self.contract_id, method_name=method_name, args=args, **options)

            return await view_function(self.connection, contract_id=self.contract_id, method_name=method_name, args=args, **options)

        return view_method

    def _create_change_method(self, method_name: str, abi: Optional[Dict[str, Any]], abi_root: Optional[Dict[str, Any]]) -> Callable[..., Any]:
        async def change_method(*args: Any, **kwargs: Any) -> Any:
            if len(args) > 1 or (args and not is_object(args[0])):
                raise PositionalArgsError()

            if len(args) == 1:
                kwargs["args"] = args[0]

            if abi:
                validate_arguments(kwargs["args"], abi, abi_root)

            return await self._change_method(method_name=method_name, **kwargs)

        return change_method

    async def _change_method(self, signer_account: Optional[Account] = None, args: Optional[Dict[str, Any]] = None, method_name: str = "", gas: Optional[int] = None, amount: Optional[int] = None, meta: Optional[str] = None, callback_url: Optional[str] = None) -> Any:
        validate_bn_like({"gas": gas, "amount": amount})

        account = self.account or signer_account

        if not account:
            raise Exception("signer_account must be specified")

        raw_result = await account.function_call(contract_id=self.contract_id, method_name=method_name, args=args, gas=gas, attached_deposit=amount, wallet_meta=meta, wallet_callback_url=callback_url)

        return get_transaction_last_result(raw_result)

def validate_bn_like(arg_map: Dict[str, Any]) -> None:
    bn_like = "number, decimal string or int"
    for arg_name, arg_value in arg_map.items():
        if arg_value is not None and not isinstance(arg_value, (int, float)) and not str(arg_value).isdecimal():
            raise ArgumentTypeError(arg_name, bn_like, arg_value)