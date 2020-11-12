using System;
using JsonWebToken;

namespace SecEventCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key defined for the 'HS256' algorithm
            var signingKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            
            // Creates a SecEvent descriptor with all its properties
            var descriptor = new SecEventDescriptor(signingKey, SignatureAlgorithm.HmacSha256)
            {
                Payload = new JwtPayload
                {
                    { "iss", "https://idp.example.com/" },
                    { "jti", "756E69717565206964656E746966696572" },
                    { "iat", 1508184845 },
                    { "aud", "636C69656E745F6964" },
                    { "toe", EpochTime.UtcNow },
                    { "events", new JsonObject
                        {
                            new AccountDisabledSecEvent
                            {
                                { "subject", new EmailSubjectIdentifier("hello@world.com") },
                                { "reason", "hijacking" }
                            }
                        }
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
