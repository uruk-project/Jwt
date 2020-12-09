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
            var descriptor = new SecEventDescriptor(signingKey, SignatureAlgorithm.HS256)
            {
                Payload = new JwtPayload
                {
                    { JwtClaimNames.Iss, "https://idp.example.com/" },
                    { JwtClaimNames.Jti, "756E69717565206964656E746966696572" },
                    { JwtClaimNames.Iat, 1508184845 },
                    { JwtClaimNames.Aud, "636C69656E745F6964" },
                    { SecEventClaimNames.Toe, EpochTime.UtcNow },
                    { SecEventClaimNames.Txn, "6964656E74" },
                    { SecEventClaimNames.Events, new JsonObject
                        {
                            new AccountDisabledSecEvent
                            {
                                { SecEvent.SubjectAttribute, new EmailSubjectIdentifier("hello@world.com") },
                                { AccountDisabledSecEvent.ReasonAttribute, "hijacking" },
                                { "custom_attribute", "hello world" }
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
