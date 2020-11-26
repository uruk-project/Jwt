# JSON Web Encryption (JWE) using Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with a nested JWS using AES encryption and a key encrypted with ECDH-ES algorithm.
The issuer use an EC public key for encrypting the token. 
The recipent use an EC private key for decrypting the token. 

## Supported encryption algorithms
 Algorithm     | Description                                                 
---------------|------------------------------------------------------------------------------
ECDH-ES        | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
ECDH-ES+A128KW | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"           
ECDH-ES+A192KW | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
ECDH-ES+A256KW | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                     


## Example code
```C#
using System;
using JsonWebToken;

namespace JweCreationSample
{
    class Program
    {
        static void Main()
        {
            // Generates the EC key for EC encryption with the algorithm 'ECDH-ES+A192KW'
            var privateEncryptionKey = ECJwk.GeneratePrivateKey(EllipticalCurve.P256, KeyManagementAlgorithm.EcdhEsAes192KW);

            // Extracts the EC public key
            var publicEncryptionKey = privateEncryptionKey.AsPublicKey();

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'ECDH-ES+A192KW' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(publicEncryptionKey, KeyManagementAlgorithm.EcdhEsAes192KW, EncryptionAlgorithm.Aes128CbcHmacSha256)
            {
                // Creates the JWS payload
                Payload = new JwsDescriptor(signatureKey, SignatureAlgorithm.HmacSha256)
                {
                    Payload = new JwtPayload
                    {
                        // Defines the JWS claims
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" }
                    }
                }
            };

            // Generates the UTF-8 string representation of the JWT
            var writer = new JwtWriter();
            var token = writer.WriteTokenString(descriptor);

            Console.WriteLine("The JWT is:");
            Console.WriteLine(descriptor);
            Console.WriteLine();
            Console.WriteLine("Its compact form is:");
            Console.WriteLine(token);
        }
    }
}
```
## Output
```JSON
The JWT is:
{
  "alg": "ECDH-ES+A192KW",
  "enc": "A128CBC-HS256",
  "kid": "NqwlBCes1pyauYPJpVo6QyiYP6VKhaDCSAUb56bOewk",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "FbKLgvaR0ughcZAoAj1f_oGgUjXCI4c_hu9Z2oKjsfU",
    "y": "tZEwAC71bKW5x9MG84rBanYyBF1k5bLK7MER8AhbS1g"
  }
}
.
{
  "alg": "HS256",
  "kid": "BkjK1uQ5hZXxCTdQ_To1gF932KVkloKB_LZYBwq_LJU"
}
.
{
  "iat": 1606391898,
  "exp": 1606395498,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiJOcXdsQkNlczFweWF1WVBKcFZvNlF5aVlQNlZLaGFEQ1NBVWI1NmJPZXdrIiwiY3R5IjoiSldUIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiRmJLTGd2YVIwdWdoY1pBb0FqMWZfb0dnVWpYQ0k0Y19odTlaMm9LanNmVSIsInkiOiJ0WkV3QUM3MWJLVzV4OU1HODRyQmFuWXlCRjFrNWJMSzdNRVI4QWhiUzFnIn19.Y6s6AQye5674UbXdz9NNebGUNjRq5_E2XnZNtTkHAK58UhRuOIH8OA.ZH0CrR_hoN5BGcSqNok0Cg.NW-nUHkSpAyDVGuT9iuwBU-8kCQaCPApLgyW6HZ4_2zK-AGTyhYCa-z4qDWbrAqgufmh4_7IyLMCkbAR5FwIPurGgK5oVjbG-9OxXyPdmVFqhiTPIZViLwGjqa0C9olKErw_Qx_nV6Fk12VKlg042CyG-BEsVhTLyyCSVUZjq84UNy2uAgfZIbkxlePcIYSxiNUB-hdQ-QikJ58sObMgVHTE4Cw1N4wsZW208-CxR_CsTDix0JvXQ0Z2ljbr4ARMEA3d76mKsnhBvJgUz_lpGo7MWfkjxmpkHkxm7V4X_z9lHQGKH6Cbg5WsLhVc6w69hE4aCqOvV4WON8y5toMF0ennjxc9bLwb2ZzaLAkFGmc.AcokbYWdcipqDmgYQ3Wo7A
```