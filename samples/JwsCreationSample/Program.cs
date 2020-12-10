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
            var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256)
            {
                Payload = new JwtPayload
                {
                    // You can use predefined claims
                    { JwtClaimNames.Iat, EpochTime.UtcNow },
                    { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                    { JwtClaimNames.Iss, "https://idp.example.com/" },
                    { JwtClaimNames.Aud, "636C69656E745F6964" },

                    // Or use custom claims 
                    { "value", "ABCEDF" }
                }
            };

            // Adds another claim
            descriptor.Payload.Add("ClaimName", new JsonObject
            {
                { "stuff1", "xyz789" },
                { "stuff2", "abc123" },
                {
                    "subObject" , new JsonObject
                    {
                        { "prop1" , "abc123" },
                        { "prop2" , "xyz789" }
                    }
                },
                {
                    "Modules" , new []
                    {
                        new JsonObject
                        {
                            { "name" , "module1" },
                            { "prop1" , "abc123" },
                            { "prop2" , "xyz789" }
                        },
                        new JsonObject
                        {
                            { "name" , "module2" },
                            { "prop1" , "abc123" },
                            { "prop2" , "xyz789" }
                        }
                    }
                }
            });


            // Adds anonymous object
            descriptor.Payload.Add("ClaimName_anonymous_type", new
            {
                stuff1 = "xyz789",
                stuff2 = "abc123",
                subObject = new
                {
                    prop1 = "abc123",
                    prop2 = "xyz789"
                },
                Modules = new[]
                {
                    new {
                        name  = "module1",
                        prop1 = "abc123",
                        prop2 = "xyz789"
                    },
                    new {
                        name  = "module2",
                        prop1 = "abc123",
                        prop2 = "xyz789"
                    }
                }
            });

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
