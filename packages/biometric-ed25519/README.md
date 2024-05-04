# biometric_ed25519

The biometric_ed25519 Python module offers a suite of tools for generating and managing Ed25519 cryptographic keys using biometric data as a seed input. This approach combines the security of elliptic curve cryptography with the uniqueness of biometric identifiers.

## Installation

Ensure you have the module installed (instructions would go here, typically via pip).

## Usage

biometrinc_ed25519 requires information coming from the browser's `window` and `navigator` objects, therefore can only be called from a python native webserver such as [Flask](https://flask.palletsprojects.com/) running and points 

### Example: Initializing `biometric-ed25519` 

#### Flask Route (Python)
``` python
from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio

app = Flask(__name__)
CORS(app)

@app.route('/init', methods=['POST'])
async def initialize():
    rp_id = request.json['rp_id']
    try:
        await init(rp_id)
        return jsonify(status="Initialized successfully"), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

```

#### HTML and JavaScript (Client-Side)
``` HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Biometric Ed25519 Initialization</title>
</head>
<body>
    <button id="initBtn">Initialize</button>
    <script>
        document.getElementById('initBtn').addEventListener('click', async () => {
            const rp_id = window.location.hostname;  // Get the hostname of the current location
            try {
                const response = await fetch('/init', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({rp_id: rp_id})
                });
                const data = await response.json();
                if (response.ok) {
                    console.log('Initialization success:', data);
                } else {
                    console.error('Initialization failed:', data.error);
                }
            } catch (error) {
                console.error('Network error:', error);
            }
        });
    </script>
</body>
</html>
```

### Example: Calling `create_key` 

You need two routes on your Flask server: one to initiate the public key creation and another to handle the response after the credential is created in the browser

#### Flask Route (Python)
``` python 
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Handle CORS if necessary

@app.route('/get_public_key_options', methods=['POST'])
async def get_public_key_options():
    # Here you would typically generate or retrieve any necessary data to create the public key
    # For simplicity, let's assume you have a function to generate these options
    public_key_options = await generate_public_key_options()  # Define this function as needed
    return jsonify(public_key_options)

@app.route('/create_key', methods=['POST'])
async def create_key_route():
    navigator_credentials_create_response = request.json['navigatorCredentialsCreateResponse']
    origin = request.headers['Origin']
    key_pair = await create_key(navigator_credentials_create_response, origin)
    return jsonify(key_pair=key_pair.to_dict())  # Ensure this method exists or convert appropriately

if __name__ == '__main__':
    app.run(debug=True)

```

#### HTML and JavaScript (Client-Side)

``` HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebAuthn Registration</title>
</head>
<body>
    <button id="registerBtn">Register</button>
    <script>
        document.getElementById('registerBtn').addEventListener('click', async () => {
            try {
                const publicKeyOptionsResponse = await fetch('/get_public_key_options', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });
                const publicKey = await publicKeyOptionsResponse.json();
                
                const credentials = await navigator.credentials.create({publicKey});
                
                const navigatorCredentialsCreateResponse = {
                    id: credentials.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credentials.rawId))),
                    type: credentials.type,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credentials.response.clientDataJSON))),
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credentials.response.attestationObject)))
                    }
                };
                
                const createKeyResponse = await fetch('/create_key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({navigatorCredentialsCreateResponse})
                });
                const keyPair = await createKeyResponse.json();
                console.log(keyPair);
            } catch (error) {
                console.error('Error:', error);
            }
        });
    </script>
</body>
</html>
``` 


Other objects required for methods in this package are `window.location.origin` and `navigator.credentials.create`


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