# Validate a JWE 
This example illustrates how to verify a JWE encoded object    . 
The recipient require a public key for validating the token. 

## Recommandation: 
The minimal key size is at least 2048 bits.

## Supported algorithms
RS256 - ECDSA using P-256 and SHA-256
RS384 - ECDSA using P-384 and SHA-384
RS512 - ECDSA using P-521 and SHA-512

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
            // Initializes the private key used for the decryption
            // This is an illustration
            // Do not hardcode a key in the source code
            var signaturekey = RsaJwk.FromBase64Url
            (
                x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
            );

            // Initializes the public key used for the signature verification
            // This is an illustration
            // Do not hardcode a key in the source code
            var signaturekey = ECJwk.FromBase64Url
            (
                crv: EllipticalCurve.P256,
                x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
            );

            // Defines the validation policy: 
            // - Require the issuer "https://idp.example.com/", with the predefined EC key, with the signature algorithm ES256
            // - Require the audience "636C69656E745F6964"
            var policy = new TokenValidationPolicyBuilder()
                           .RequireIssuer("https://idp.example.com/", key, SignatureAlgorithm.EcdsaSha256)
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
The token is {"alg":"ES256"}.{"exp":1500007200,"iat":2000007200,"iss":"https://idp.example.com/","aud":"636C69656E745F6964"}
```