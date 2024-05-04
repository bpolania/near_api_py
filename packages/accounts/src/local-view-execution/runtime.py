import hashlib
from typing import Any, Dict, List, Optional
from wasmer import engine, Store, Module, Instance

class ContractState:
    def __init__(self, key: bytes, value: bytes):
        self.key = key
        self.value = value

class RuntimeCtx:
    def __init__(self, contract_id: str, contract_state: List[ContractState], block_height: int, block_timestamp: int, method_args: str):
        self.contract_id = contract_id
        self.contract_state = contract_state
        self.block_height = block_height
        self.block_timestamp = block_timestamp
        self.method_args = method_args

class RuntimeConstructorArgs(RuntimeCtx):
    def __init__(self, contract_id: str, contract_state: List[ContractState], block_height: int, block_timestamp: int, method_args: str, contract_code: str):
        super().__init__(contract_id, contract_state, block_height, block_timestamp, method_args)
        self.contract_code = contract_code

class Runtime:
    def __init__(self, args: RuntimeConstructorArgs):
        self.context = args
        self.wasm = self.prepare_wasm(args.contract_code.encode('base64'))
        self.memory = bytearray(1024 * 1024 * 1024)  # 1GB memory
        self.registers: Dict[str, bytes] = {}
        self.logs: List[str] = []
        self.result = b''

    def read_utf16_cstr(self, ptr: int) -> str:
        arr: List[int] = []
        mem = memoryview(self.memory)
        key = ptr // 2
        while mem[key * 2:key * 2 + 2] != b'\x00\x00':
            arr.append(int.from_bytes(mem[key * 2:key * 2 + 2], 'little'))
            key += 1
        return bytes(arr).decode('utf-16')

    def read_utf8_cstr(self, length: int, ptr: int) -> str:
        arr: List[int] = []
        mem = memoryview(self.memory)
        key = ptr
        for i in range(length):
            if mem[key] == 0:
                break
            arr.append(mem[key])
            key += 1
        return bytes(arr).decode('utf-8')

    def storage_read(self, key_len: int, key_ptr: int) -> Optional[bytes]:
        storage_key = self.memory[key_ptr:key_ptr + key_len]
        state_val = [obj.value for obj in self.context.contract_state if obj.key == storage_key]
        if not state_val:
            return None
        return state_val[0] if len(state_val) == 1 else state_val

    def prepare_wasm(self, input: bytes) -> bytes:
        parts: List[bytes] = []
        magic = input[:4]
        if magic.decode('utf-8') != '\0asm':
            raise Exception('Invalid magic number')
        version = int.from_bytes(input[4:8], 'little')
        if version != 1:
            raise Exception(f'Invalid version: {version}')
        offset = 8
        parts.append(input[:offset])

        def decode_leb128() -> int:
            nonlocal offset
            result = 0
            shift = 0
            while True:
                byte = input[offset]
                offset += 1
                result |= (byte & 0x7f) << shift
                shift += 7
                if not (byte & 0x80):
                    break
            return result

        def decode_limits() -> Dict[str, int]:
            nonlocal offset
            flags = input[offset]
            offset += 1
            has_max = flags & 0x1
            initial = decode_leb128()
            max_val = decode_leb128() if has_max else None
            return {'initial': initial, 'max': max_val}

        def decode_string() -> str:
            nonlocal offset
            length = decode_leb128()
            result = input[offset:offset + length]
            offset += length
            return result.decode('utf-8')

        def encode_leb128(value: int) -> bytes:
            result: List[int] = []
            while True:
                byte = value & 0x7f
                value >>= 7
                if value != 0:
                    byte |= 0x80
                result.append(byte)
                if value == 0:
                    break
            return bytes(result)

        def encode_string(value: str) -> bytes:
            result = value.encode('utf-8')
            return encode_leb128(len(result)) + result

        while offset < len(input):
            section_start = offset
            section_id = input[offset]
            offset += 1
            section_size = decode_leb128()
            section_end = offset + section_size

            if section_id == 5:
                # Memory section
                parts.append(b'\x05\x01\x00')
            elif section_id == 2:
                # Import section
                section_parts: List[bytes] = []
                num_imports = decode_leb128()
                for _ in range(num_imports):
                    import_start = offset
                    decode_string()
                    decode_string()
                    kind = input[offset]
                    offset += 1

                    skip_import = False
                    if kind == 0:
                        # Function import
                        decode_leb128()
                    elif kind == 1:
                        # Table import
                        offset += 1
                        decode_limits()
                    elif kind == 2:
                        # Memory import
                        decode_limits()
                        skip_import = True
                    elif kind == 3:
                        # Global import
                        offset += 1
                        offset += 1
                    else:
                        raise Exception(f'Invalid import kind: {kind}')

                    if not skip_import:
                        section_parts.append(input[import_start:offset])

                import_memory = encode_string('env') + encode_string('memory') + b'\x02\x00' + encode_leb128(1)
                section_parts.append(import_memory)

                section_data = encode_leb128(len(section_parts)) + b''.join(section_parts)
                parts.append(b'\x02' + encode_leb128(len(section_data)) + section_data)
            elif section_id == 7:
                # Export section
                section_parts: List[bytes] = []
                num_exports = decode_leb128()
                for _ in range(num_exports):
                    export_start = offset
                    decode_string()
                    kind = input[offset]
                    offset += 1
                    decode_leb128()

                    if kind != 2:
                        # Pass through all exports except memory
                        section_parts.append(input[export_start:offset])

                section_data = encode_leb128(len(section_parts)) + b''.join(section_parts)
                parts.append(b'\x07' + encode_leb128(len(section_data)) + section_data)
            else:
                parts.append(input[section_start:section_end])
            offset = section_end

        return b''.join(parts)

    def get_register_length(self, register_id: int) -> int:
        return len(self.registers.get(str(register_id), b''))

    def read_from_register(self, register_id: int, ptr: int) -> None:
        self.memory[ptr:ptr + len(self.registers[str(register_id)])] = self.registers[str(register_id)]

    def get_current_account_id(self, register_id: int) -> None:
        self.registers[str(register_id)] = self.context.contract_id.encode('utf-8')

    def input_method_args(self, register_id: int) -> None:
        self.registers[str(register_id)] = self.context.method_args.encode('utf-8')

    def get_block_height(self) -> int:
        return self.context.block_height

    def get_block_timestamp(self) -> int:
        return self.context.block_timestamp

    def sha256(self, value_len: int, value_ptr: int, register_id: int) -> None:
        value = self.memory[value_ptr:value_ptr + value_len]
        self.registers[str(register_id)] = hashlib.sha256(value).digest()

    def return_value(self, value_len: int, value_ptr: int) -> None:
        self.result = self.memory[value_ptr:value_ptr + value_len]

    def panic(self, message: str) -> None:
        raise Exception(f'panic: {message}')

    def abort(self, msg_ptr: int, filename_ptr: int, line: int, col: int) -> None:
        msg = self.read_utf16_cstr(msg_ptr)
        filename = self.read_utf16_cstr(filename_ptr)
        message = f'{msg} {filename}:{line}:{col}'
        if not msg or not filename:
            raise Exception('abort: String encoding is bad UTF-16 sequence.')
        raise Exception(f'abort: {message}')

    def append_to_log(self, length: int, ptr: int) -> None:
        self.logs.append(self.read_utf8_cstr(length, ptr))

    def read_storage(self, key_len: int, key_ptr: int, register_id: int) -> int:
        result = self.storage_read(key_len, key_ptr)
        if result is None:
            return 0
        self.registers[str(register_id)] = result
        return 1

    def has_storage_key(self, key_len: int, key_ptr: int) -> int:
        result = self.storage_read(key_len, key_ptr)
        return 1 if result is not None else 0

    def get_host_imports(self) -> Dict[str, Any]:
        return {
            'register_len': self.get_register_length,
            'read_register': self.read_from_register,
            'current_account_id': self.get_current_account_id,
            'input': self.input_method_args,
            'block_index': self.get_block_height,
            'block_timestamp': self.get_block_timestamp,
            'sha256': self.sha256,
            'value_return': self.return_value,
            'abort': self.abort,
            'log_utf8': self.append_to_log,
            'log_utf16': self.append_to_log,
            'storage_read': self.read_storage,
            'storage_has_key': self.has_storage_key,
            'panic': lambda: self.panic('explicit guest panic'),
            'panic_utf8': lambda length, ptr: self.panic(self.read_utf8_cstr(length, ptr)),
            # Not implemented
            'epoch_height': lambda: self.not_implemented('epoch_height'),
            'storage_usage': lambda: self.not_implemented('storage_usage'),
            'account_balance': lambda: self.not_implemented('account_balance'),
            'account_locked_balance': lambda: self.not_implemented('account_locked_balance'),
            'random_seed': lambda: self.not_implemented('random_seed'),
            'ripemd160': lambda: self.not_implemented('ripemd160'),
            'keccak256': lambda: self.not_implemented('keccak256'),
            'keccak512': lambda: self.not_implemented('keccak512'),
            'ecrecover': lambda: self.not_implemented('ecrecover'),
            'validator_stake': lambda: self.not_implemented('validator_stake'),
            'validator_total_stake': lambda: self.not_implemented('validator_total_stake'),
            # Prohibited
            'write_register': lambda: self.prohibited_in_view('write_register'),
            'signer_account_id': lambda: self.prohibited_in_view('signer_account_id'),
            'signer_account_pk': lambda: self.prohibited_in_view('signer_account_pk'),
            'predecessor_account_id': lambda: self.prohibited_in_view('predecessor_account_id'),
            'attached_deposit': lambda: self.prohibited_in_view('attached_deposit'),
            'prepaid_gas': lambda: self.prohibited_in_view('prepaid_gas'),
            'used_gas': lambda: self.prohibited_in_view('used_gas'),
            'promise_create': lambda: self.prohibited_in_view('promise_create'),
            'promise_then': lambda: self.prohibited_in_view('promise_then'),
            'promise_and': lambda: self.prohibited_in_view('promise_and'),
            'promise_batch_create': lambda: self.prohibited_in_view('promise_batch_create'),
            'promise_batch_then': lambda: self.prohibited_in_view('promise_batch_then'),
            'promise_batch_action_create_account': lambda: self.prohibited_in_view('promise_batch_action_create_account'),
            'promise_batch_action_deploy_contract': lambda: self.prohibited_in_view('promise_batch_action_deploy_contract'),
            'promise_batch_action_function_call': lambda: self.prohibited_in_view('promise_batch_action_function_call'),
            'promise_batch_action_function_call_weight': lambda: self.prohibited_in_view('promise_batch_action_function_call_weight'),
            'promise_batch_action_transfer': lambda: self.prohibited_in_view('promise_batch_action_transfer'),
            'promise_batch_action_stake': lambda: self.prohibited_in_view('promise_batch_action_stake'),
            'promise_batch_action_add_key_with_full_access': lambda: self.prohibited_in_view('promise_batch_action_add_key_with_full_access'),
            'promise_batch_action_add_key_with_function_call': lambda: self.prohibited_in_view('promise_batch_action_add_key_with_function_call'),
            'promise_batch_action_delete_key': lambda: self.prohibited_in_view('promise_batch_action_delete_key'),
            'promise_batch_action_delete_account': lambda: self.prohibited_in_view('promise_batch_action_delete_account'),
            'promise_results_count': lambda: self.prohibited_in_view('promise_results_count'),
            'promise_result': lambda: self.prohibited_in_view('promise_result'),
            'promise_return': lambda: self.prohibited_in_view('promise_return'),
            'storage_write': lambda: self.prohibited_in_view('storage_write'),
            'storage_remove': lambda: self.prohibited_in_view('storage_remove'),
        }

    @staticmethod
    def not_implemented(name: str) -> None:
        raise NotImplementedError(f'method not implemented: {name}')

    @staticmethod
    def prohibited_in_view(name: str) -> None:
        raise Exception(f'method not available for view calls: {name}')
    
    async def execute(self, method_name: str) -> Dict[str, Any]:
        # Create a new store
        store = Store(engine.JIT(engine.Cranelift))

        # Compile the WebAssembly module
        module = Module(store, self.wasm)

        # Create an instance of the module
        instance = Instance(module, imports={
            'env': {
                'memory': self.memory,
                **self.get_host_imports()
            }
        })

        # Get the exported function by name
        call_method = getattr(instance.exports, method_name, None)

        if call_method is None:
            raise Exception(f"Contract method '{method_name}' does not exist in contract {self.context.contract_id} for block id {self.context.block_height}")

        # Call the exported function
        call_method()

        return {
            'result': self.result,
            'logs': self.logs
        }