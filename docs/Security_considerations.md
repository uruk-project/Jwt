# Security considerations

## Security basic concepts
There is 4 objectives: 
* Integrity: Data must not be tampered and can be trusted
* Authenticity: Data comes from an expected issuer
* Confidentiality: Data must be kept secret from unauthorized party
* Non-repudiation: There is a proof of the data issuer

|                          |  Integrity | Authenticity | Confidentiality | Non-repudiation |
|-------------------------:|-----------:|-------------:|----------------:|----------------:|
| HMAC                     | X          | X            |                 |                 |
| Digital signature        | X          | X            |                 | X               |
| Authenticated Encryption | X          | X            | X               |                 |

## Algorithm choice 

### Transit non-confidential data to itself
When the token issuer and the token recipient is the same party, the best choice is a symmetric signature algorithm HSXXX, providing integrity & authenticity.
Example: The `state` parameter is used to store session data between multiple redirections on the browser. 

Use a JWS with HS256/HS384/HS512 algorithms.

| Signature algorithm |  Key exchange algorithm | Encryption algorithm |
|--------------------:|------------------------:|---------------------:|
| HS256               | N/A                     | N/A                  |
| HS384               | N/A                     | N/A                  |
| HS512               | N/A                     | N/A                  |

###	Transit non-confidential data to another party
When the token issuer and the token recipient are not the same party, the best choice is an asymmetric signature algorithm RSXXX/PSXXX/ESXXX, providing integrity, authenticity and non-repudiation.

Example: The access_token in OAuth2 is used to trasmit authorization data between the authorization server and the resource server. 

Use a JWS with RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512.
RSXXX algorithms are more widely supported, but if the token recipient support ESXXX algorithm, it might be prefered.

###	Transit confidential data to itself
When the token issuer and the token recipient is the same party, and the data to transmit needs to be opaque, 
the best choice is a symmetric signature algorithm HSXXX, providing integrity, and a direct/symmetric algorithm for authenticity and confidentiality.

Example: The `state` parameter is used to store session confidential data between multiple redirections on the browser. 
Use a JWE with either "dir" key algorithm and any AES encryption algorithm, or a JWE with a symmetric key management algorithm and any AES encryption algorithm, or 

| Signature algorithm |  Key exchange algorithm | Encryption algorithm | Recommended |
|--------------------:|------------------------:|---------------------:|-------------|
| Any                 | dir                     | A128CBC-HS256        | X           |
| Any                 | dir                     | A128GCM              | X           |
| Any                 | A128KW                  | A128CBC-HS256        | X           |
| Any                 | A128KW                  | A128GCM              | X           |
| Any                 | A128GCMKW               | A128CBC-HS256        | X           |
| Any                 | A128GCMKW               | A128GCM              | X           |
| Any                 | dir                     | A192CBC-HS384        | X           |
| Any                 | dir                     | A192GCM              | X           |
| Any                 | A192KW                  | A192CBC-HS384        | X           |
| Any                 | A192KW                  | A192GCM              | X           |
| Any                 | A192GCMKW               | A192CBC-HS384        | X           |
| Any                 | A192GCMKW               | A192GCM              | X           |
| Any                 | dir                     | A256CBC-HS512        | X           |
| Any                 | dir                     | A256GCM              | X           |
| Any                 | A256KW                  | A256CBC-HS512        | X           |
| Any                 | A256KW                  | A256GCM              | X           |
| Any                 | A256GCMKW               | A256CBC-HS512        | X           |
| Any                 | A256GCMKW               | A256GCM              | X           |

We recommand to have a combination of the same strength for all the algorithms. 
For example A128GCMKW / A128GCM.
Even if it is possible, avoid to mix like A192GCMKW / A128GCM.

###	Transit confidential data to another party
When the token issuer and the token recipient are not the same party, and the data to transmit needs to be opaque, 
the best choice is an asymmetric signature algorithm like RSXXX/PSXXX/ESXXX, providing integrity, authenticity and non-repudiation, 
and an asymmetric algorithm for authenticity and confidentiality. The AES algorithm is always used for the encryption of the payload.

Example: The access_token in OAuth2 is used to trabsmit confidential authorization data between the authorization server and the resource server. 
Use a JWE with any asymmetric key exchange algorithm, and any AES encryption algorithm. The content of the JWE is a JWS that is sign with an asymmetric signature algorithm
There is no link between the asymmetric signature algorithm and the asymmetric key exchange algorithm. RSA can be use for the signature and ECDH for the key exchange aswell.


| Signature algorithm |  Key exchange algorithm | Encryption algorithm |
|--------------------:|------------------------:|---------------------:|
| RS256               | dir                     | A128CBC-HS256        |
| RS384               | dir                     | A128CBC-HS256        |
| RS512               | dir                     | A128CBC-HS256        |
| PS256               | dir                     | A128CBC-HS256        |
| PS384               | dir                     | A128CBC-HS256        |
| PS512               | dir                     | A128CBC-HS256        |
| ES256               | dir                     | A128CBC-HS256        |
| ES256X              | dir                     | A128CBC-HS256        |
| ES384               | dir                     | A128CBC-HS256        |
| ES512               | dir                     | A128CBC-HS256        |
|--------------------:|------------------------:|---------------------:|


###	Special cases
TBD

### Algorithms

| Signature algorithm |  Situable for self-issued token | Situable for token issed for another party |
|--------------------:|--------------------------------:|-------------------------------------------:|
| HS256               | Yes                             | No                                         |
| HS384               | Yes                             | No                                         |
| HS512               | Yes                             | No                                         |
| RS256               | Yes*                            | Yes                                        |
| RS384               | Yes*                            | Yes                                        |
| RS512               | Yes*                            | Yes                                        |
| PS256               | Yes*                            | Yes                                        |
| PS384               | Yes*                            | Yes                                        |
| PS512               | Yes*                            | Yes                                        |
| ES256               | Yes*                            | Yes                                        |
| ES256X              | Yes*                            | Yes                                        |
| ES384               | Yes*                            | Yes                                        |
| ES512               | Yes*                            | Yes                                        |

Yes* means it is possible, but might not be optimal.

|  Key exchange algorithm | Situable for self-issued token | Situable for token issed for another party |
|------------------------:|-------------|-------------|
| dir                     | Yes         | No          |
| A128KW                  | Yes         | No          |
| A128GCMKW               | Yes         | No          |
| A192KW                  | Yes         | No          |
| A192GCMKW               | Yes         | No          |
| A256KW                  | Yes         | No          |
| A256GCMKW               | Yes         | No          |
| PBES2-HS256+A128KW      | Yes         | No          |
| PBES2-HS384+A192KW      | Yes         | No          |
| PBES2-HS512+A256KW      | Yes         | No          |
| RSA1_5                  | Yes*        | Yes         |
| RSA-OAEP                | Yes*        | Yes         |
| RSA-OAEP-256            | Yes*        | Yes         |
| RSA-OAEP-384            | Yes*        | Yes         |
| RSA-OAEP-512            | Yes*        | Yes         |
| ECDH-ES                 | Yes*        | Yes         |
| ECDH-ES+A128KW          | Yes*        | Yes         |
| ECDH-ES+A192KW          | Yes*        | Yes         |
| ECDH-ES+A256KW          | Yes*        | Yes         |

Yes* means it is possible, but might not be optimal.

## Key length equivalent
|  RSA key length (bits) | ECC key length (bits) | 
|-----------------------:|----------------------:|
| 3072                   | 256                   | 
| 7680                   | 384                   | 
| 15360                  | 521                   |  

In 2020, the recommended *minimal* key length for RSA is 3072. ECC algorithms require smaller key length.

### TD ; DR
Use HSXXX when the you do not require non-repudation.
Otherwise:
Use RSXXX/PSXXX when the performance is required on the recipient side.
Use ESXXX when the performance is required on the issuer side.


Hash algorithms has nearly no impact on the performance. The throughput of SHA2 algorithms are much higher that the associated signing algorithms.

Outside of any security consideration, HMAC SHA2 give the best performance, for signature generation as well for signature verification. 
This is a symmetric algorithm, and should be used only when the repudiation is not an issue (ie. the issuer is the recipient).

All RSA algorithms (RSXXX & PSXXX) are similaire in term of performance. 
RSA algorithms performs faster for verification that ECDSA algorithms, but it is the opposite 


## Encryption algorithm choice

## Key exchange algorithm choice
