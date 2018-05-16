using JsonWebToken;
using System;

namespace Performance
{
    class Program
    {
        private const string Token1 = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";
        private static readonly JsonWebKey SharedKey = JsonWebKey.FromJson("{" +
                                                   "\"kty\": \"oct\"," +
                                                   "\"use\": \"sig\"," +
                                                   "\"kid\": \"kid-hs256\"," +
                                                   "\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
                                                   "\"alg\": \"HS256\"" +
                                                   "}");
        private static readonly JsonWebTokenReader _reader = new JsonWebTokenReader(SharedKey);
        private static readonly JsonWebTokenWriter _writer = new JsonWebTokenWriter();

        static void Main(string[] args)
        {
            Console.WriteLine("Starting...");

            //for (int i = 0; i < 1000000; i++)
            //{
            //    var result = _reader.TryReadToken(Token1, new TokenValidationParameters
            //    {
            //        ValidateAudience = false,
            //        ValidateIssuer = false
            //    });
            //}

            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            var token = new JsonWebTokenDescriptor()
            {
                IssuedAt = issuedAt,
                Expires = expires,
                Issuer = issuer,
                Audience = audience,
                SigningKey = SharedKey
            };

            for (int i = 0; i < 1000000; i++)
            {
                var result = _writer.WriteToken(token);
            }
        }
    }
}
