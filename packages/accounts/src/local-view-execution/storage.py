from typing import Optional
from lru import LRU

class ContractState:
    def __init__(self, key: bytes, value: bytes):
        self.key = key
        self.value = value

class StorageData:
    def __init__(self, block_height: int, block_timestamp: int, contract_code: str, contract_state: list[ContractState]):
        self.block_height = block_height
        self.block_timestamp = block_timestamp
        self.contract_code = contract_code
        self.contract_state = contract_state

class StorageOptions:
    def __init__(self, max: int):
        self.max = max

class Storage:
    MAX_ELEMENTS = 100

    def __init__(self, options: StorageOptions = StorageOptions(max=MAX_ELEMENTS)):
        self.cache = LRU(options.max)
        self.block_heights = {}

    def load(self, block_ref: dict) -> Optional[StorageData]:
        if 'blockId' not in block_ref:
            return None

        block_id = block_ref['blockId']

        # block hash is passed, so get its corresponding block height
        if isinstance(block_id, str) and len(block_id) == 44:
            block_id = self.block_heights.get(block_id)

        # get cached values for the given block height
        return self.cache.get(block_id)

    def save(self, block_hash: str, data: StorageData) -> None:
        self.block_heights[block_hash] = data.block_height
        self.cache[data.block_height] = data