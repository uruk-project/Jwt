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
                           .RequireSignature("https://idp.example.com/", key, SignatureAlgorithm.HS256)
                           .RequireAudience("636C69656E745F6964")
                           .Build();

            // Try to parse the JWT. Its return false 
            if (Jwt.TryParse("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.YrrT1Ddp1ampsDd2GwYZoTz_bUnLt_h--f16wsWBedk", policy, out Jwt jwt))
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
