# JSON Web Encryption (JWE) using AES Key wrapping
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with a nested JWS using AES encryption and a key also encrypted with the AES algorithm.
The issuer and audience must previously share a secret key. 

## Recommandation: 
Use JWE using AES key wrapping only if the issuer and the recipient are the same. This avoid to share a secret. 
A common use case would be to represent the OAuth2 state parameter as a JWE. 
In this case, the JWE is issued by the client application, then retrieved by the same client application. 

If you are using symmetric algorithms for both signature and encryption, you must not use the same key.

## Supported encryption algorithms
 Algorithm | Description                                               | Key length  
-----------|-----------------------------------------------------------|-----------
A128KW     | AES Key Wrap with default initial value using 128-bit key | 128 bits                               
A192KW     | AES Key Wrap with default initial value using 192-bit key | 192 bits                               
A256KW     | AES Key Wrap with default initial value using 256-bit key | 256 bits                               
A128GCMKW  | Key wrapping with AES GCM using 128-bit key               | 128 bits
A192GCMKW  | Key wrapping with AES GCM using 192-bit key               | 192 bits
A256GCMKW  | Key wrapping with AES GCM using 256-bit key               | 256 bits

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
            // Generates the symmetric key for AES encryption with the algorithm 'A256GCMKW'
            var sharedEncryptionKey = SymmetricJwk.GenerateKey(KeyManagementAlgorithm.Aes256GcmKW);

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'A256GCMKW' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(sharedEncryptionKey, KeyManagementAlgorithm.Aes256GcmKW, EncryptionAlgorithm.Aes256CbcHmacSha512)
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
  "alg": "A256GCMKW",
  "enc": "A256CBC-HS512",
  "kid": "c_8-4PIaAMYPXwIbwFEome-BHq7yV7e6Tkr14Wx5mPk",
  "cty": "JWT",
  "iv": "FwAAAAAAAADLAAAA",
  "tag": "8eEZQVay4nrz-MqAuSrlWQ"
}
.
{
  "alg": "HS256",
  "kid": "alnOaG6vrsRmyzxmnhLjLmTtMGqybWMlJTMd02wgNf8"
}
.
{
  "iat": 1606397290,
  "exp": 1606400890,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiY184LTRQSWFBTVlQWHdJYndGRW9tZS1CSHE3eVY3ZTZUa3IxNFd4NW1QayIsImN0eSI6IkpXVCIsIml2IjoiRndBQUFBQUFBQURMQUFBQSIsInRhZyI6IjhlRVpRVmF5NG5yei1NcUF1U3JsV1EifQ.KrQ7hEbB_0Ei4mDnNN9adU5PIpiyGuALQz_6kym-LSIqcHHdZ1n4NbtMpsraxIegx6z7FiTR0w9EBa507PNbdQ.342dpjjnCCMXJts0p_UmOg.rkZ6-kBLRb5peVBbSxrGZzx-Mh1_StI9t65aa9QQccIZNu-TLuFTEcEw8ECDEmVtPQxo-Gx5wgaea0AAnRibwIw-7nyT78ExTcZSvKNxBmmXpUa1WsUUJQJUUIx1T1qlV-7ckj7yqUlOt8Qggl9-vVlvtp0fCymdsqTmGxp_pkv35H69titHda76vpO1m3UOHAijvvTge1ZcnkLxsGFEZwTAr7TVayMUt6l6mVLsrpBwNL4Xtkyrl0QFvrpYGoWqi-gKSd-CF9F8TmrAsXng04MfjsvGlO5TY87urRx3ypTqZxdDIj7MGbDQtMXdVVBtoLcZIj7_g4jlksiR51c41G5bjNTeYQrReJwuqVRL1vg.5CGPgeaIQ87U5sBaBApfsMf-bRTNmw2gR5MxjXVmSN8
```