# JSON Web Encryption (JWE) using Password-Based Encryption Scheme (PBES2)
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with a nested JWS using AES encryption and a key encrypted with PBES2 algorithm.
The issuer use an passphrase public key for encrypting the token. 
The recipent use the same passphrase for decrypting the token. 

## Supported encryption algorithms
 Algorithm         | Description                                                 
-------------------|------------------------------------------------------------------------------
PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping           
PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping
PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping                     

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
            // Generates the password-based key for PBES encryption with the algorithm 'PBES2-HS256+A128KW'
            var pbesKey = PasswordBasedJwk.FromPassphrase("Thus from my lips, by yours, my sin is purged.", iterationCount: 4096, saltSizeInBytes: 16);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'PBES2-HS256+A128KW' and 'enc' with value 'A256CBC-HS512'
            var descriptor = new PlaintextJweDescriptor(pbesKey, KeyManagementAlgorithm.Pbes2HS256A128KW, EncryptionAlgorithm.A256CbcHS512)
            {
                // Creates the JWS payload
                Payload = "The true sign of intelligence is not knowledge but imagination."
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
  "alg": "PBES2-HS256+A128KW",
  "enc": "A256CBC-HS512",
  "kid": "gG41M-7TySn0qRHlgcua4xWS11v1PvoFpO2uC21_3JI",
  "typ": "plain",
  "p2s": "c_ORk4HSsqZD2LvVeCUHqg",
  "p2c": 4096
}
.
The true sign of intelligence is not knowledge but imagination.

Its compact form is:
eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiZ0c0MU0tN1R5U24wcVJIbGdjdWE0eFdTMTF2MVB2b0ZwTzJ1QzIxXzNKSSIsInR5cCI6InBsYWluIiwicDJzIjoiY19PUms0SFNzcVpEMkx2VmVDVUhxZyIsInAyYyI6NDA5Nn0.5NCv0_RIPFbtZOEuBYWlo4-fa7jqSgfr2JGiFc_x4x6tw4RkcthaQhm0skOYSyJedT1cQY1hH3FoU_e0w3SxcOCBABQOd6y5.9FNO8sAlPKowUaytW7LpAA.QeSbFKHdSnMuquXKpGkbSYoBD8h4Pp_53J8e41FbQzM9n-zV0YT42lecFoq1cJbG84xeIhySOiXaW4UDUltTrw.4mTExamTEKNSpPDMCB1pdikVKNmp5CYfEFRtXx_CUTw
```