import json
import base64
from typing import Any, Union

from types import ViewStateResult, BlockReference, CodeResult, PositionalArgsError
from .connection import Connection
from utils import print_tx_outcome_logs
from .interface import ViewFunctionCallOptions

def parse_json_from_raw_response(response: bytes) -> Any:
    return json.loads(response.decode())

def bytes_json_stringify(input: Any) -> bytes:
    return json.dumps(input).encode()

def validate_args(args: Any) -> None:
    is_uint8array = hasattr(args, 'byteLength') and args.byteLength == len(args)
    if is_uint8array:
        return

    if isinstance(args, (list, tuple)) or not isinstance(args, dict):
        raise PositionalArgsError()

def encode_js_contract_args(contract_id: str, method: str, args: Any) -> bytes:
    return contract_id.encode() + b'\0' + method.encode() + b'\0' + args.encode()

async def view_state(
    connection: Connection,
    account_id: str,
    prefix: Union[str, bytes],
    block_query: BlockReference = {'finality': 'optimistic'}
) -> list[dict[str, bytes]]:
    response = await connection.provider.query(ViewStateResult, {
        'request_type': 'view_state',
        **block_query,
        'account_id': account_id,
        'prefix_base64': base64.b64encode(prefix.encode() if isinstance(prefix, str) else prefix).decode()
    })
    values = response['values']

    return [
        {
            'key': base64.b64decode(entry['key']),
            'value': base64.b64decode(entry['value'])
        }
        for entry in values
    ]

async def view_function(
    connection: Connection,
    options: ViewFunctionCallOptions
) -> Any:
    contract_id = options['contract_id']
    method_name = options['method_name']
    args = options.get('args', {})
    parse = options.get('parse', parse_json_from_raw_response)
    stringify = options.get('stringify', bytes_json_stringify)
    js_contract = options.get('js_contract', False)
    block_query = options.get('block_query', {'finality': 'optimistic'})

    validate_args(args)

    if js_contract:
        encoded_args = encode_js_contract_args(contract_id, method_name, json.dumps(args) if args else '')
    else:
        encoded_args = stringify(args)

    result = await connection.provider.query(CodeResult, {
        'request_type': 'call_function',
        **block_query,
        'account_id': connection.jsvm_account_id if js_contract else contract_id,
        'method_name': 'view_js_contract' if js_contract else method_name,
        'args_base64': base64.b64encode(encoded_args).decode()
    })

    if result.get('logs'):
        print_tx_outcome_logs({'contract_id': contract_id, 'logs': result['logs']})

    if result.get('result') and len(result['result']) > 0:
        return parse(base64.b64decode(result['result']))

    return None