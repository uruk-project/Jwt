using System;
using JsonWebToken;

namespace MultiIssuersValidationSample
{
    class Program
    {
        static void Main()
        {
            // This sample demonstrates how to validate a token that may come form different issuers. 
            // This is common if you have to support multiple Authorization Servers.
            var keyIssuer1 = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            var policyIssuer1 = new TokenValidationPolicyBuilder()
                           .RequireSignature(keyIssuer1, SignatureAlgorithm.HmacSha256)
                           .RequireAudience("636C69656E745F6964")
                           .RequireIssuer("https://idp1.example.com/")
                           .Build();

            var keyIssuer2 = SymmetricJwk.FromBase64Url("9dobXhxMWH9PoLsKRdv1qp0bEqJm4YNd8JRaTxes8i4");
            var policyIssuer2 = new TokenValidationPolicyBuilder()
                           .RequireSignature(keyIssuer2, SignatureAlgorithm.HmacSha256)
                           .RequireAudience("9656E745F6964636C6")
                           .RequireIssuer("https://idp2.example.com/")
                           .Build();

            var keyIssuer3 = SymmetricJwk.FromBase64Url("lh2TJcMdPyNLhfNp0nYLAFM_R0UEXVoZ9N7ife4ZT-A");
            var policyIssuer3 = new TokenValidationPolicyBuilder()
                           .RequireSignature(keyIssuer3, SignatureAlgorithm.HmacSha256)
                           .RequireAudience("F6964636C69656E745")
                           .RequireIssuer("https://idp3.example.com/")
                           .Build();

            var policies = new[] { policyIssuer1, policyIssuer2, policyIssuer3 };

            var token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAzLmV4YW1wbGUuY29tLyIsImF1ZCI6IkY2OTY0NjM2QzY5NjU2RTc0NSJ9.a6RiTht8kyTDL9SZVX9kUye7dJL9YSZxJPbAyaaw3QE";

            for (int i = 0; i < policies.Length; i++)
            {
                // Try to read the token with the different policies
                if (Jwt.TryParse(token, policies[i], out var jwt))
                {
                    Console.WriteLine($"The token is issued by '{jwt.Payload["iss"].GetString()}':");
                    Console.WriteLine(jwt);
                    break;
                }

                Console.WriteLine($"Failed to read the token for the issuer '{policies[i].RequiredIssuer}'.");
                Console.WriteLine("  Reason: " + jwt.Error.Status);
            }
        }
    }
}