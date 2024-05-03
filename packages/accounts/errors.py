import json
from typing import List

class UnsupportedSerializationError(Exception):
    def __init__(self, method_name: str, serialization_type: str):
        super().__init__(f"Contract method '{method_name}' is using an unsupported serialization type {serialization_type}")

class UnknownArgumentError(Exception):
    def __init__(self, actual_arg_name: str, expected_arg_names: List[str]):
        super().__init__(f"Unrecognized argument '{actual_arg_name}', expected '{json.dumps(expected_arg_names)}'")

class ArgumentSchemaError(Exception):
    def __init__(self, arg_name: str, errors: List[dict]):
        super().__init__(f"Argument '{arg_name}' does not conform to the specified ABI schema: '{json.dumps(errors)}'")

class ConflictingOptions(Exception):
    def __init__(self):
        super().__init__("Conflicting contract method options have been passed. You can either specify ABI or a list of view/call methods.")