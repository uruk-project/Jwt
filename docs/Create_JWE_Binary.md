# JSON Web Encryption (JWE) with binary data as payload
A JWE is a JWT that contains an encrypted payload. 
The payload is commonly a JWS, but it can also be binary data or plain text.

This example illustrates how to create a JWE with binary data as payload. 

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
  "kid": "gwiVOn0lBQBFB_xzv6Zpwmy2eohA51SNJlVreZ_fkdE",
  "typ": "octet-stream"
}
.
System.Byte[]

Its compact form is:
eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZ3dpVk9uMGxCUUJGQl94enY2WnB3bXkyZW9oQTUxU05KbFZyZVpfZmtkRSIsInR5cCI6Im9jdGV0LXN0cmVhbSJ9..32_fG1T3BSAj1aPRkA6alA.PLDQi-nVdyEuUqiHpsIyrw.E559sqmTOEkwXZK-uVR_IA
```