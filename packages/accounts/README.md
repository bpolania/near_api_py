## near-api-py/accounts

A collection of classes, functions, and types for interacting with accounts and contracts in the NEAR Python API.

# Modules

* account.py: Contains the Account class with methods to transfer NEAR, manage account keys, sign transactions, etc.
* account_multisig.py: Defines the AccountMultisig class, which represents a multisig deployed Account requiring multiple keys to sign transactions.
* account_2fa.py: Provides the Account2FA class, an extension of AccountMultisig used in conjunction with 2FA provided by near-contract-helper.
* account_creator.py: Includes classes for creating NEAR accounts.
* contract.py: Defines the Contract class, which represents a deployed smart contract with view and/or change methods.
* connection.py: Contains the Connection class, a record containing the information required to connect to NEAR RPC.
* constants.py: Defines account-specific constants.
* types.py: Provides account-specific types.