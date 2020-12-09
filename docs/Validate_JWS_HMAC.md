# JSON Web Signature (JWS) using HMAC
This example illustrate how to verify a JWS encoded object using HMAC (Hash-based Message Authentication Code). 
The producer and consumer must previously share a secret. 

## Recommandation: 
Use JWS using HMAC only if the issuer and the recipient are the same. This avoid to share a secret. 

## Supported algorithms
HS256 - HMAC using SHA-256, requires a secret of at least 256 bits 
HS384 - HMAC using SHA-384, requires a secret of at least 384 bits 
HS512 - HMAC using SHA-512, requires a secret of at least 512 bits 

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
            // Initializes the shared secret as a symmetric key of 256 bits
            var key = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");

            // Defines the validation policy: 
            // - Require the issuer "https://idp.example.com/", with the predefined key, with the signature algorithm HS256
            // - Require the audience "636C69656E745F6964"
            var policy = new TokenValidationPolicyBuilder()
                           .RequireIssuer("https://idp.example.com/", key, SignatureAlgorithm.HS256)
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
The token is {"alg":"HS256"}.{"exp":1500007200,"iat":2000007200,"iss":"https://idp.example.com/","aud":"636C69656E745F6964"}
```