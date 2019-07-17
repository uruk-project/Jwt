using System;
using JsonWebToken;

namespace UnsecureJwtCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a JWS descriptor with all its properties
            var descriptor = new JwsDescriptor()
            {
                Algorithm = SignatureAlgorithm.None,
                IssuedAt = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.AddHours(1),
                Issuer = "https://idp.example.com/",
                Audience = "636C69656E745F6964"
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
