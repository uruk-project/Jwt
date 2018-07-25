using JsonWebToken;
using System;

namespace Performance
{
    class Program
    {

        private static readonly SymmetricJwk _key = SymmetricJwk.FromBase64Url("U1oK6e4BAR4kKTdyA1OqEFYwX9pIrswuUMNt8qW4z-k");
        private static readonly SymmetricJwk _keyToWrap = SymmetricJwk.FromBase64Url("gXoKEcss-xFuZceE6B3VkEMLw-f0h9tGfyaheF5jqP8");

        private const string Token1 = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";
        private static readonly JsonWebKey SharedKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "kid-hs256",
            K = "GdaXeVyiJwKmz5LFhcbcng",
            Alg = "HS256"
        };
        private static readonly JsonWebKey EncryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithms.Aes256KW);
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
            var jwe = new JweDescriptor
            {
                Key = EncryptionKey,
                EncryptionAlgorithm = ContentEncryptionAlgorithms.Aes128CbcHmacSha256,
                Payload = token
            };
            //var jwt = _writer.WriteToken(jwe);

            //Parallel.For(0, 10, _ =>
            //{
            //for (int i = 0; i < 1000000; i++)
            //{
            //    var result = _reader.TryReadToken(jwt.AsSpan(), policy);
            //}

            //for (int i = 0; i < 10000000; i++)
            //{
            //    var jwt = _writer.WriteToken(jwe);
            //}
            ////});


            var kwp = new SymmetricKeyWrapProvider(_key, KeyManagementAlgorithms.Aes256KW);
            var kwp2 = new SymmetricKeyWrapProviderOld(_key, KeyManagementAlgorithms.Aes256KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize(ContentEncryptionAlgorithms.Aes128CbcHmacSha256)];
            var unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            while (true)
            {
                var wrapped = kwp.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten);
                var unwrapped = kwp.TryUnwrapKey(wrappedKey, unwrappedKey, out int keyWrappedBytesWritten);

                //var wrapped2 = kwp2.TryWrapKey(_keyToWrap.RawK, wrappedKey, out var bytesWritten2);
                //var unwrapped2 = kwp2.TryUnwrapKey(wrappedKey, unwrappedKey, out keyWrappedBytesWritten);
            }
        }
    }
}
