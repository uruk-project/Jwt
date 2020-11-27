# JSON Web Encryption (JWE) with plain text as payload
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with plain text data as payload. 

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
            // Creates a symmetric key for encryption
            var encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'dir' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new PlaintextJweDescriptor(encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.A128CbcHS256)
            {
                // Creates the plain text payload
                Payload = "Live long and prosper."
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
  "kid": "JuNyUNJXT2tTEnFqD6diFPEB0UKN5ochpJlT1-Y7DeA",
  "typ": "plain"
}
.
Live long and prosper.

Its compact form is:
eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiSnVOeVVOSlhUMnRURW5GcUQ2ZGlGUEVCMFVLTjVvY2hwSmxUMS1ZN0RlQSIsInR5cCI6InBsYWluIn0..8nnUg6GYXqxwl3ceMp6Z7w.Qlm1_QvkASvKiJN6M7YYIdnV2d9vlJPbltTslf3N_PE.eUeoHG3SesZZDHTQhS7bwg
```