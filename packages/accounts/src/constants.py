from utils import parse_near_amount

MULTISIG_STORAGE_KEY = '__multisigRequest'

MULTISIG_ALLOWANCE = parse_near_amount('1')

# TODO: the JS api suggsted a different gas value for different requests (can reduce gas usage dramatically)
MULTISIG_GAS = 100000000000000

MULTISIG_DEPOSIT = 0

MULTISIG_CHANGE_METHODS = ['add_request', 'add_request_and_confirm', 'delete_request', 'confirm']

MULTISIG_CONFIRM_METHODS = ['confirm']