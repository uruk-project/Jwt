using System;
using JsonWebToken;

namespace JwtCreationSample
{
    class Program
    {
        static void Main(string[] args)
        {
            var key = new SymmetricJwk("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
            var descriptor = new JwsDescriptor()
            {
                Key = key,
                ExpirationTime = new DateTime(2034, 7, 14, 4, 40, 0, DateTimeKind.Utc),
                IssuedAt = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
                Issuer = "https://idp.example.com/",
                Audience = "636C69656E745F6964"
            };

            var writer = new JwtWriter();
            var token = writer.WriteTokenString(descriptor);

            Console.WriteLine("The token is:");
            Console.WriteLine(token);
        }
    }
}
