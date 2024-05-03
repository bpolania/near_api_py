# NEAR Python SDK - Accounts Module

A collection of classes, functions, and types for interacting with accounts and contracts in the NEAR Python API.

## Modules

* [account.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/account.py): Contains the Account class with methods to transfer NEAR, manage account keys, sign transactions, etc.
* [account_multisig.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/account_multisig.py): Defines the AccountMultisig class, which represents a multisig deployed Account requiring multiple keys to sign transactions.
* [account_2fa.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/account_2fa.py): Provides the Account2FA class, an extension of AccountMultisig used in conjunction with 2FA provided by near-contract-helper.
* [account_creator.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/account_creator.py): Includes classes for creating NEAR accounts.
* [contract.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/contract.py): Defines the Contract class, which represents a deployed smart contract with view and/or change methods.
* [connection.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/connection.py): Contains the Connection class, a record containing the information required to connect to NEAR RPC.
* [constants.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/constants.py): Defines account-specific constants.
* [types.py](https://github.com/bpolania/near_api_py/blob/main/packages/accounts/src/types.py): Provides account-specific types.

### Contributions

Contributions to the `crypto` module are welcome. If you have suggestions for improvement or have identified issues, please open an issue or pull request in our GitHub repository.

### License

The `crypto` module and the entire NEAR Python SDK are licensed under the MIT License. For more details, see the LICENSE file in the root directory of this project.
