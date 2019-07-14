using System;
using JsonWebToken;

namespace CreatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
        private static readonly JwtWriter writer = new JwtWriter();

        private static JwsDescriptor descriptor = new JwsDescriptor
        {
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964",
            Key = signingKey
        };

        private static void Main()
        {
            Console.WriteLine("Starting...");
            writer.EnableHeaderCaching = false;
            while (true)
            {
               var token = writer.WriteToken(descriptor);
            }
        }
    }
}
