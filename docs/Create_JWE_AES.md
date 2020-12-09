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
            var sharedEncryptionKey = SymmetricJwk.GenerateKey(KeyManagementAlgorithm.A256GcmKW);

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'A256GCMKW' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(sharedEncryptionKey, KeyManagementAlgorithm.A256GcmKW, EncryptionAlgorithm.A256CbcHS512)
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
  "alg": "A256GCMKW",
  "enc": "A256CBC-HS512",
  "kid": "TFcEncN031xahCdylt3LWautA_TqtV5rHAhIRdlUfww",
  "cty": "JWT",
  "iv": "WxA_uBJ7WjZNQRwg",
  "tag": "zFooprII_Uxk2mrjE2kmQw"
}
.
{
  "alg": "HS256",
  "kid": "fqcE621cy_nNuSdI-gPyqcJkVvXpx-mGTwIKE4nBXOU"
}
.
{
  "iat": 1606939593,
  "exp": 1606943193,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiVEZjRW5jTjAzMXhhaENkeWx0M0xXYXV0QV9UcXRWNXJIQWhJUmRsVWZ3dyIsImN0eSI6IkpXVCIsIml2IjoiV3hBX3VCSjdXalpOUVJ3ZyIsInRhZyI6InpGb29wcklJX1V4azJtcmpFMmttUXcifQ.LLI608bxdYUGK2gjTtFJGGu7A_lHpndyDXJIOnSdU_wfovaqp9UiOVmM9c9IPMmcLv-76fqxPKG8kE1PdYUQZg.Vpam6yomQsHTBYIBmE8DMg.zWrcSTINWUD_uiw8iFHNmuhYy1MTqEhug4Ni6AuXJzgrUpDaUlcmZkZaw02rp74tnuPShTjtUY8xaXPh2SSSIOFv17ckWewB6NyorBUtatvItGmVQWkwb2fS2PWVCXb6cXGrV1TL9I2f9eUaKmdjRcys6MGIxDfKELKDAQ24L3G-2DhdymNzmaIkKIqfM2BE6yr8dttaa9hRvTc-DRFNP5Em5dzrSJ_aOtUdvCkRaQrMBdusfiaJsoX47yVGQWBV6lxzSxDS_MuzutZN2fnhA7WtHZlXIftvAN1rRkXz3AxfA4jKro2tJa_clPQrG8fz_RgU4MqjYIotvVEvC8VpJ9DcboBE-aG7sanp3cCluWg.Y1s19sggSyBKhlaAbFlNmppBpNpY3u4RRhxFHVuJ194
```