# JSON Web Signature (JWS) using RSA
This example illustrates how to verify a JWS encoded object using RSA signature. 
The producer use a RSA private key for signing the token. 
The consumer use a RSA public key for validating the token. 

## Recommandation: 
The minimal key size is at least 2048 bits.

## Supported algorithms
RS256 - RSASSA-PKCS1-v1_5 using SHA-256
RS384 - RSASSA-PKCS1-v1_5 using SHA-384
RS512 - RSASSA-PKCS1-v1_5 using SHA-512
PS256 - RSASSA-PSS using SHA-256 and MGF1 with SHA-256
PS384 - RSASSA-PSS using SHA-384 and MGF1 with SHA-384
PS512 - RSASSA-PSS using SHA-512 and MGF1 with SHA-512

## Example code
```C#
using System;
using JsonWebToken;

namespace JwsValidationSample
{
    class Program
    {
        static void Main()
        {
            // Initializes the RSA public key of 2048 bits
            var key = RsaJwk.FromBase64Url
            (
                n: "w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ",
                e: "AQAB",
                alg: SignatureAlgorithm.RsaSha256
            );

            // Defines the validation policy: 
            // - Require the issuer "https://idp.example.com/", with the predefined RSA key, with the signature algorithm RS256
            // - Require the audience "636C69656E745F6964"
            var policy = new TokenValidationPolicyBuilder()
                           .RequireIssuer("https://idp.example.com/", key, SignatureAlgorithm.RsaSha256)
                           .RequireAudience("636C69656E745F6964")
                           .Build();

            // Try to parse the JWT. It returns false if the token is invalid
            if(Jwt.TryParse("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.YrrT1Ddp1ampsDd2GwYZoTz_bUnLt_h--f16wsWBedk", policy, out Jwt jwt))
            {
                Console.WriteLine("The token is " + jwt);
            }
            else
            {
                Console.WriteLine("Failed to read the token. Error: " + Environment.NewLine + jwt.Error);
            }

            // Do not forget to dispose the Jwt, or you may suffer of GC impacts
            jwt.Dispose();
        }
    }
}
```
## Output
```JSON
The token is {"alg":"RS256"}.{"exp":1500007200,"iat":2000007200,"iss":"https://idp.example.com/","aud":"636C69656E745F6964"}
```