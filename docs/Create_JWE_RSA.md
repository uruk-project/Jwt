# JSON Web Encryption (JWE) using RSA encryptiony
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with a nested JWS using AES encryption and a key encrypted with RSA algorithm.. 
The issuer use a RSA public key for encrypting the token. 
The recipent use a RSA private key for decrypting the token. 

## Recommandation: 
A key size of 2048 bits or larger is required.
RSA1_5 is depreciated and should not be used.

## Supported encryption algorithms
 Algorithm     | Description                                    | Key length
---------------|------------------------------------------------|-----------
 RSA1_5        | RSAES-PKCS1-v1_5                               | 2048+ bits
 RSA-OAEP      | RSAES OAEP using default parameters            | 2048+ bits
 RSA-OAEP-256  | RSAES OAEP using SHA-256 and MGF1 with SHA-256 | 2048+ bits
 RSA-OAEP-384  | RSAES OAEP using SHA-384 and MGF1 with SHA-384 | 2048+ bits
 RSA-OAEP-512  | RSAES OAEP using SHA-512 and MGF1 with SHA-512 | 2048+ bits

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
            // Generates the RSA key for RSA encryption with the algorithm 'RSA-OAEP-256'
            var privateEncryptionKey = RsaJwk.GeneratePrivateKey(KeyManagementAlgorithm.RsaOaep256);

            // Extracts the RSA public key
            var publicEncryptionKey = privateEncryptionKey.AsPublicKey();

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'RSA-OAEP-256' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.RsaOaep256, EncryptionAlgorithm.A128CbcHS256)
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
  "alg": "RSA-OAEP-256",
  "enc": "A128CBC-HS256",
  "kid": "jX81kSRETHI-X5Sm2A6-xg39NLuu0B0O-lloyrrc2uk",
  "cty": "JWT"
}
.
{
  "alg": "HS256",
  "kid": "1-jUn58Li49xTDZERDslq_EEhvVF6eZlqE6Zwx6k2QI"
}
.
{
  "iat": 1606390581,
  "exp": 1606394181,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoialg4MWtTUkVUSEktWDVTbTJBNi14ZzM5Tkx1dTBCME8tbGxveXJyYzJ1ayIsImN0eSI6IkpXVCJ9.Hd8st15WsT97Fa4SrOC6O6mgN42kiQGsj3Cb4-eTWAky2EAikINPbOEwuLfDSa83hVx_S99TOUhbC7exZ8prrlZOprf9wU-r28gg3o2cSh1DvfQ7A-24_rmiAd-bYwM6eTYzOcEz7eRkL-Y_2rL_yKYRq9pQzOvgzTMrk5VjZvKyfMIsnRB846P-EdeilDAEjViGJ0AIcYWXT2zlfInhuT4Ioi5wkGsPklUWH0-e1FfdHl2UHPLm0a-Y5UQvgdDs5SeF3zwBSQoBKmRxU_rHPiETFtrPYGEiWd_tnXTdrmJSF6GEqT17H3Jcx4Wd3bbTHXxGwU6busZrXKL2khpvBA.O0zz7FniMrPIeBHqXOwbDg.YrO553Yp6cpPUPjV1_gTJ-XxZGA6rizt-CX1wmI0dOBxsn1s7gsAlzeTH3ydFgPj1-TFvaOjKvr-83dIgXtThPzyZLhbJFP1Rw4VymdmSl-51idf-qEzwhSOmko4cFdRkGkC6tFWjo3NE_Icy2tXbpdalxbNMZQVwzyP80VYOM5czcJAUpgsohRQpQOSh_X6qyy66AxQWPCNXyoiSfrINr8u00rBv7KGbIfCnad67q1WvzEVN5Fd-gaTi4BiM2eh6wbavTgsV1Irkw04xnSQ6bP0R_riwySnSioGjcaA8w4CMx8rnyaLQ-SNJg-SFMtlAVEVOGhbzZcE8cBQ8FiCCEDgc5qtN8n8SBYbJ7kX7bo.WC9nIRA5lubU5QNxY1NuZQ
```