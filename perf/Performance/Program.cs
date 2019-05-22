using System;
using System.Collections.Generic;
using System.Text;
using JsonWebToken;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;

namespace Performance
{
    internal class Program
    {
        private static readonly Jwk SharedKey = new SymmetricJwk("GdaXeVyiJwKmz5LFhcbcng")
        {
            Use = JwkUseNames.Sig.ToArray(),
            Kid = "kid-hs256",
            Alg = SignatureAlgorithm.HmacSha256
        };
        private static readonly Jwk EncryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithm.Aes256KW);
        private static readonly JwtReader _reader = new JwtReader(SharedKey, EncryptionKey);
        private static readonly JwtWriter _writer = new JwtWriter();
        private static readonly TokenValidationPolicy policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(SharedKey)
                    .Build();

        private static void Main(string[] args)
        {
            Console.WriteLine("Starting...");
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var jws = new JwsDescriptor()
            {
                //IssuedAt = issuedAt,
                //ExpirationTime = expires,
                //Issuer = "https://idp.example.com/",
                //Audience = "636C69656E745F6964",
                Key = SharedKey, 
                Algorithm = SharedKey.Alg
            };

            var jwt = _writer.WriteToken(jws);
            _reader.EnableHeaderCaching = false;
            _writer.EnableHeaderCaching = false;
            while (true)
            {
                //var result = _reader.TryReadToken(jwt.AsSpan(), TokenValidationPolicy.NoValidation);
                _writer.WriteToken(jws);
            }
        }
    }
}

