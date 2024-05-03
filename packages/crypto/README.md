# NEAR Python SDK - Crypto Module

## Modules

The `crypto` module includes several key components designed to work with NEAR's cryptographic requirements:

- **PublicKey**: A class that represents a public key capable of verifying signatures. This class is essential for validating transactions and data integrity within the NEAR ecosystem.

- **KeyPairBase**: An abstract base class that defines the standard structure and functionality for a cryptographic key pair. This class provides the foundational methods that all specific key pair implementations must adhere to.

- **KeyPair**: An abstract extension of `KeyPairBase`, this class includes static methods for parsing and generating key pairs. It serves as the template from which specific key pair types are derived.

- **KeyPairEd25519**: A concrete implementation of `KeyPairBase`, using the Ed25519 signing algorithm. This class is tailored for high-performance cryptographic operations and is the recommended choice for handling NEAR protocol's key management tasks.

- **Constants**: This module contains keypair-specific constants that are used throughout the cryptographic operations. These constants ensure that key pair operations maintain consistency and adhere to predefined standards.

### Contributions

Contributions to the `crypto` module are welcome. If you have suggestions for improvement or have identified issues, please open an issue or pull request in our GitHub repository.

### License

The `crypto` module and the entire NEAR Python SDK are licensed under the MIT License. For more details, see the LICENSE file in the root directory of this project.
