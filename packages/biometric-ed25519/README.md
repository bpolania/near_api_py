# biometric_ed25519

The biometric_ed25519 Python module offers a suite of tools for generating and managing Ed25519 cryptographic keys using biometric data as a seed input. This approach combines the security of elliptic curve cryptography with the uniqueness of biometric identifiers.

## Installation

Ensure you have the module installed (instructions would go here, typically via pip).

## Usage

biometrinc_ed25519 requires information coming from the browser's `window` and `navigator` objects, therefore can only be called from a python native webserver such as [Flask]() running and points 

### Example: calling `get_public_key`

To call the get_public_key function from an HTML page in a Flask application, you need to set up an appropriate route that handles HTTP requests from the client side.:

#### Flask Route (Python)
``` python
from flask import Flask, request, jsonify
from flask_cors import CORS  # You might need to install this package
import asyncio

app = Flask(__name__)
CORS(app)  # This line is to handle CORS if your client is on a different origin

@app.route('/get_public_key', methods=['POST'])
async def handle_get_public_key():
    data = request.json
    credential = data.get('credential')
    public_key = await get_public_keys(credential)  # Assuming your function is adjusted to accept right parameters
    return jsonify(public_key=public_key)

if __name__ == '__main__':
    app.run(debug=True)
```

#### HTML and JavaScript (Client-Side)
``` HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Get Public Key</title>
<script>
async function getPublicKey(credential) {
    const response = await fetch('/get_public_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({credential: credential})
    });
    const data = await response.json();
    console.log(data.public_key);
}
</script>
</head>
<body>
    <button onclick="getPublicKey(credentialData)">Get Public Key</button>
</body>
</html>

```
<!-- ```python
from biometric_ed25519 import create_key, get_keys

# To register a user with userName
key = await create_key(userName)

# To retrieve keys for a user with userName
keys = await get_keys(userName)
``` -->
Due to the nature of Elliptic Curve cryptography, `get_keys` returns two possible public key pairs. To accurately identify and utilize the correct public key pair created by `create_key`, it's crucial to implement logic that preserves the public key pair from `create_key` and retrieves them with `get_keys`, selecting the correct one from the two available pairs.

## Use Case

1. Check if a given username exists against an RPC endpoint.
2. User Registration: A user creates authentication credentials in a browser using their biometric fingerprint, linked to their desired username by calling create_key.
3. Account Creation: Use the public key obtained from step 2 to create a NEAR account associated with the given username.
4. User Authentication:
    * When the user returns to authenticate, use get_keys to retrieve the two possible public key pairs.
    * Create a NEAR connection using the username.
    * Retrieve a list of access keys and check if one of the public key pairs from get_keys exists in the list.
    * If a matching public key is found, use it to authenticate the session.

## License

This repository and its contents are distributed under the terms of both the MIT license and the Apache License (Version 2.0). Refer to LICENSE-MIT and LICENSE-APACHE files for detailed terms and conditions.