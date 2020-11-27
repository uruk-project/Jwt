# JSON Web Signature (JWS) using ECDSA (Elliptic Curve Digital Signature Algorithm)
A JWS is a JWT that contains an JSON payload and a signature. 

This example illustrates how to create a JWS using Elliptic Curve Digital Signature Algorithm.
The issuer use a EC private key for signing the token. 
The recipent use a EC public key for validating the token. 

## Supported encryption algorithms
 Algorithm | Description                     
-----------|-------------------------------
ES256      | ECDSA using P-256 and SHA-256
ES384      | ECDSA using P-384 and SHA-384
ES512      | ECDSA using P-521 and SHA-512

## Example code
```C#
using System;
using JsonWebToken;

namespace JwsCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates the EC key defined for the 'PS512' signature algorithm
            var privateKey = ECJwk.GeneratePrivateKey(SignatureAlgorithm.EcdsaSha512);

            // Creates the JWS descriptor 
            // The descriptor sets the 'alg' with value 'PS512'
            var descriptor = new JwsDescriptor(privateKey, SignatureAlgorithm.EcdsaSha512)
            {
                Payload = new JwtPayload
                {
                    // Defines the JWS claims
                    { JwtClaimNames.Iat, EpochTime.UtcNow },
                    { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                    { JwtClaimNames.Iss, "https://idp.example.com/" },
                    { JwtClaimNames.Aud, "636C69656E745F6964" }
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
  "alg": "ES512",
  "kid": "O5y6LRswKAAzomsLRb-MRFgOt0fZrw3FwIpKyS3wEy8"
}
.
{
  "iat": 1606422294,
  "exp": 1606425894,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJFUzUxMiIsImtpZCI6Ik81eTZMUnN3S0FBem9tc0xSYi1NUkZnT3QwZlpydzNGd0lwS3lTM3dFeTgifQ.eyJpYXQiOjE2MDY0MjIyOTQsImV4cCI6MTYwNjQyNTg5NCwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.AKz7Q9-OWBibd8Dfc-YnS8rdyluSJkLJ7deKE2TkTyEexoKGxnm2mFOGlhG07rSzON0SG0Edu9yAGB2eL-aFf34KAOCQfzqpC7ySNDNLLF4lRsGidTLDq7NxHZ17uwpn9GJiOBeeSIs7SQUTXG3_oacImcJFgLs9yTTWY1KrZaOUL1Am
```