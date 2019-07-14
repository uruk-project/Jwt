using System;
using JsonWebToken;

namespace ValidatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
        private static readonly JwtReader _reader = new JwtReader(signingKey);
        private static readonly JwtWriter _writer = new JwtWriter();
        private static readonly JwsDescriptor jws = new JwsDescriptor()
        {
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964",
            Key = signingKey
        };
        private static readonly byte[] token = _writer.WriteToken(jws);

        private static void Main()
        {
            Console.WriteLine("Starting...");
            _reader.EnableHeaderCaching = false;
            while (true)
            {
                var result = _reader.TryReadToken(token, TokenValidationPolicy.NoValidation);
            }
        }
    }
}
