using JsonWebToken;
using JsonWebToken.Performance;
using System;
using System.Threading.Tasks;

namespace Performance
{
    class Program
    {
        private const string Token1 = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";
        private static readonly JsonWebKey SharedKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "kid-hs256",
            K = "GdaXeVyiJwKmz5LFhcbcng",
            Alg = "HS256"
        };
        private static readonly JsonWebTokenReader _reader = new JsonWebTokenReader(SharedKey);
        private static readonly JsonWebTokenWriter _writer = new JsonWebTokenWriter();
        private static readonly TokenValidationPolicy policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(SharedKey)
                    .Build();

        static void Main(string[] args)
        {
            Console.WriteLine("Starting...");

            //for (int i = 0; i < 5000000; i++)
            //{
            //    var result = _reader.TryReadToken(Token1, parameters);
            //}

            //foreach (var token in new [] { "enc-small" })
            //{
            //    var result = _reader.TryReadToken(Tokens.ValidTokens[token].AsSpan(), new TokenValidationBuilder().RequireSignature(Tokens.SigningKey).Build());

            //}
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            var token = new JwsDescriptor()
            {
                IssuedAt = issuedAt,
                ExpirationTime = expires,
                Issuer = issuer,
                Audience = audience,
                Key = SharedKey
            };

            //SymmetricJwk.EnableCaching = true;

            Parallel.For(0, 10, _ =>
            {
                for (int i = 0; i < 100000; i++)
                {
                    var result = _writer.WriteToken(token);
                }
            });
        }
    }
}
