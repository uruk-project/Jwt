# JSON Web Encryption (JWE) using Direct encryption
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with a nested JWS using direct AES encryption. 
The issuer and recipient must previously share a secret. 

## Recommandation: 
Use JWE using direct encryption only if the issuer and the audience are the same. This avoid to share a secret. 
A common use case would be to represent the OAuth2 state parameter as a JWE. 
In this case, the JWE is issued by the client application, then retrieved by the same client application. 

## Supported encryption algorithms
 Algorithm     | Description                                                 | Key length
---------------|-------------------------------------------------------------|-----------
 A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | 256 bits
 A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | 384 bits
 A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | 512 bits
 A128GCM       | AES GCM using 128-bit key                                   | 128 bits
 A192GCM       | AES GCM using 192-bit key                                   | 192 bits
 A256GCM       | AES GCM using 256-bit key                                   | 256 bits

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
            // Generates the symmetric key for direct encryption with the algorithm 'A128CBC-HS256'
            var encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256);

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'dir' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.A128CbcHS256)
            {  
                // Creates the JWS payload
                Payload = new JwsDescriptor(signatureKey, SignatureAlgorithm.HS256)
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
  "alg": "dir",
  "enc": "A128CBC-HS256",
  "kid": "nimNvu8zyqaPhj2E3yihJXYJWE0ogsEBWWmyl9P21E0",
  "cty": "JWT"
}
.
{
  "alg": "HS256",
  "kid": "39bLzAmT_G-XZDTz-NwX9Clbn_l_7quyymVnIMR9WDQ"
}
.
{
  "iat": 1606383856,
  "exp": 1606387456,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoibmltTnZ1OHp5cWFQaGoyRTN5aWhKWFlKV0Uwb2dzRUJXV215bDlQMjFFMCIsImN0eSI6IkpXVCJ9..n2AH4dJouSlqy4F2o6LOnw.JitQ7UVLpszHUZPLkKPmF8G7f0C-0PxSKADJ1JgIa1agz73u-6iGXxxwRjFIZihWTWjtp3fGDq9xgUXCYFI_Kd9JMwcMdJOV3inRTUlb1zkYz6l-ghY4SVEgNvhbGuCs8ph5vJGVQl589UABcoIKJn6j0Ul37sWv9IOKrDJDj8A6r9WgI87psIWXZzzabjjjZh8uzXrEo0d7OK6ffMfS06DtOBIu4drwByx2UdSJHQCCj-SWxhQRbH6TvCC1WgikbuVSWMXyOHiw0Pei4wna1UEGpKYIYf9ANv7UnlHotrRg22ohVvwCyo-OaThl_kWlPc--b_NPDi0lpt7apMuo1QFv9PP12A19roaNBY_O8NI.PZooQsC9btQDfoMxymUmLA
```