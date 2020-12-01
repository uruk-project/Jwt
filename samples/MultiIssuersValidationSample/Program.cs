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
            var keyIssuer2 = SymmetricJwk.FromBase64Url("9dobXhxMWH9PoLsKRdv1qp0bEqJm4YNd8JRaTxes8i4R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            var keyIssuer3 = SymmetricJwk.FromBase64Url("lh2TJcMdPyNLhfNp0nYLAFM_R0UEXVoZ9N7ife4ZT-A");
            var policyMultiIssuer = new TokenValidationPolicyBuilder()
                            .RequireSignature("https://idp1.example.com/", keyIssuer1, SignatureAlgorithm.HS256)
                            .RequireSignature("https://idp2.example.com/", keyIssuer2, SignatureAlgorithm.HS512)
                            .RequireSignature("https://idp3.example.com/", keyIssuer3, SignatureAlgorithm.HS256)
                            .RequireAudience("F6964636C69656E745")
                            .Build();

            var token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAzLmV4YW1wbGUuY29tLyIsImF1ZCI6IkY2OTY0NjM2QzY5NjU2RTc0NSJ9.a6RiTht8kyTDL9SZVX9kUye7dJL9YSZxJPbAyaaw3QE";

            // Try to read the token with the different policies
            if (Jwt.TryParse(token, policyMultiIssuer, out var jwt))
            {
                Console.WriteLine($"The token is issued by '{jwt.Payload["iss"].GetString()}':");
                Console.WriteLine(jwt);

                jwt.Dispose();
            }
            else
            {
                Console.WriteLine("Failed to read the token.");
                Console.WriteLine("  Reason: " + jwt.Error.Status);
                jwt.Dispose();
            }
        }
    }
}