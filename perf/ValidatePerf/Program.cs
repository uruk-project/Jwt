using System;
using System.Text;
using JsonWebToken;
using JsonWebToken.Cryptography;

namespace ValidatePerf
{
    class Program
    {
        //private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);
        //private static readonly Jwk encryptionKey1 = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A256Gcm);
        //private static readonly Jwk encryptionKey2 = ECJwk.GeneratePrivateKey(EllipticalCurve.P256, KeyManagementAlgorithm.EcdhEsA256KW);
        //private static readonly Jwk encryptionKey3 = RsaJwk.GeneratePrivateKey(4096, KeyManagementAlgorithm.RsaOaep256);
        //private static readonly ReadOnlyMemory<byte> _jws = CreateJws();
        //private static readonly TokenValidationPolicy _policy =
        //    new TokenValidationPolicyBuilder()
        //    .RequireIssuer("https://idp.example.com/", signingKey, SignatureAlgorithm.HS256)
        //    .Build();
        private static readonly byte[] simpleJson = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"null\":null,\"array\":[\"hello\",\"world\"]}");
        private static readonly byte[] complexJson = Encoding.UTF8.GetBytes(@"{
          ""iss"": ""https://idp.example.com/"",
          ""jti"": ""756E69717565206964656E746966696572"",
          ""iat"": 1594824782,
          ""aud"": ""636C69656E745F6964"",
          ""txn"": ""meN8paRMSS"",
          ""toe"": 1508184845,
          ""events"": {
            ""https://schemas.openid.net/secevent/risc/event-type/account-enabled"": {
              ""subject"": {
                ""subject_type"": ""account"",
                ""uri"": ""acct:john.doe%40example.com@service.com""
              },
              ""device"": {
                ""subject_type"": ""user_agent"",
                ""user_agent"": ""Mozilla"",
                ""ip_address"": ""192.168.0.2"",
                ""ip_port"": 8765
              }
            }
          }
        }");

        private static void Main()
        {
            Console.WriteLine("Starting...");
            //var span = _jws.Span;
            //var writer = new JwtWriter();
            while (true)
            {
                ParseSimpleJson();
                ParseComplexJson();
            }
        }

        private static void ParseSimpleJson()
        {
            JwtPayloadDocument.TryParsePayload(simpleJson, null, TokenValidationPolicy.NoValidation, out var payload, out var error);
        }
        private static void ParseComplexJson()
        {
            JwtPayloadDocument.TryParsePayload(complexJson, null, TokenValidationPolicy.NoValidation, out var payload, out var error);
        }

        //private static byte[] Encode6(JwtWriter writer)
        //{
        //    JweDescriptor descriptor = new JweDescriptor(encryptionKey1, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A256Gcm)
        //    {
        //        Payload = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None)
        //        {
        //            Payload = new JwtPayload
        //            {
        //                { JwtClaimNames.Iat, 1500000000L },
        //                { JwtClaimNames.Exp, 2000000000L },
        //                { JwtClaimNames.Iss, "https://idp.example.com/" },
        //                { JwtClaimNames.Aud, "636C69656E745F6964" },
        //                { JwtClaimNames.Sub, "admin@example.com" },
        //                { JwtClaimNames.Jti, "12345667890" }
        //            }
        //        }
        //    };

        //    return writer.WriteToken(descriptor);
        //}

        //private static ReadOnlyMemory<byte> CreateJws()
        //{
        //    var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256)
        //    {
        //        Payload = new JwtPayload
        //        {
        //            { JwtClaimNames.Iat, 1500000000L },
        //            { JwtClaimNames.Exp, 2000000000L },
        //            { JwtClaimNames.Iss, "https://idp.example.com/" },
        //            { JwtClaimNames.Aud, "636C69656E745F6964" },
        //            { JwtClaimNames.Sub, "admin@example.com" },
        //            { JwtClaimNames.Jti, "12345667890" }
        //        }
        //    };

        //    var bufferWriter = new System.Buffers.ArrayBufferWriter<byte>();
        //    var context = new EncodingContext(bufferWriter, null, 0, false);
        //    descriptor.Encode(context);
        //    return bufferWriter.WrittenMemory;
        //}
    }
}
