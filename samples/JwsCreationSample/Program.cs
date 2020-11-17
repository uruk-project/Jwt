using System;
using JsonWebToken;

namespace JwsCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key defined for the 'HS256' algorithm
            var signingKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");

            // Creates a JWS descriptor with all its properties
            var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256)
            {
                Payload = new JwtPayload
                {
                    // You can use predefined claims
                    { Claims.Iat, EpochTime.UtcNow },
                    { Claims.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                    { Claims.Iss, "https://idp.example.com/" },
                    { Claims.Aud, "636C69656E745F6964" },

                    // Or use custom claims 
                    { "value", "ABCEDF" }
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
