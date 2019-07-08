using JsonWebToken;
using System;

namespace JwtValidationSample
{
    class Program
    {
        static void Main()
        {
            var key = new SymmetricJwk("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            var policy = new TokenValidationPolicyBuilder()
                           .RequireSignature(key, SignatureAlgorithm.HmacSha256)
                           .RequireAudience("636C69656E745F6964")
                           .RequireIssuer("https://idp.example.com/")
                           .Build();

            var reader = new JwtReader();
            var result = reader.TryReadToken("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.YrrT1Ddp1ampsDd2GwYZoTz_bUnLt_h--f16wsWBedk", policy);
            if (result.Succedeed)
            {
                Console.WriteLine("The token is " + result.Token);
            }
            else
            {
                Console.WriteLine("Failed to read the token. Reason: " + Environment.NewLine + result.Status);
            }
        }
    }
}
