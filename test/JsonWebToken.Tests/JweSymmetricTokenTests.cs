using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweSymmetricTokenTests
    {
        private readonly SymmetricJwk _symmetric128Key = new SymmetricJwk("LxOcGxlu169Vxa1A7HyelQ");

        private readonly SymmetricJwk _symmetric192Key = new SymmetricJwk("kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc");

        private readonly SymmetricJwk _symmetric256Key = new SymmetricJwk("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");

        private readonly SymmetricJwk _symmetric384Key = new SymmetricJwk("V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm");

        private readonly SymmetricJwk _symmetric512Key = new SymmetricJwk("98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg");

        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256);

        [Fact]
        public void Encode_Decode_NotSupported()
        {
            var writer = new JwtWriter();

            var descriptor = new JweDescriptor
            {
                EncryptionAlgorithm = new EncryptionAlgorithm(-99, "unsupported", 0, SignatureAlgorithm.None, 0, EncryptionType.NotSupported),
                Algorithm = KeyManagementAlgorithm.Direct,
                Payload = new JwsDescriptor
                {
                    SigningKey = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256,
                    Subject = "Alice"
                }
            };

            Assert.Throws<NotSupportedException>(() =>
            {
                var token = writer.WriteToken(descriptor);
            });
        }

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithms))]
        public void Encode_Decode(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var writer = new JwtWriter();
            var encryptionKey = SelectKey(enc.Name, alg.Name);

            var descriptor = new JweDescriptor
            {
                EncryptionKey = encryptionKey,
                EncryptionAlgorithm = enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    SigningKey = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                .WithDecryptionKey(encryptionKey)
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);

            Assert.True(jwt.Payload.TryGetClaim("sub", out var sub));
            Assert.Equal("Alice", sub.GetString());
        }

        private SymmetricJwk SelectKey(string enc, string alg)
        {
            switch (alg)
            {
                case "A128KW":
                case "A128GCMKW":
                    return _symmetric128Key;
                case "A192KW":
                case "A192GCMKW":
                    return _symmetric192Key;
                case "A256KW":
                case "A256GCMKW":
                    return _symmetric256Key;
                case "dir":
                    switch (enc)
                    {
                        case "A128CBC-HS256":
                            return _symmetric256Key;
                        case "A128GCM":
                            return _symmetric128Key;
                        case "A192CBC-HS384":
                            return _symmetric384Key;
                        case "A192GCM":
                            return _symmetric192Key;
                        case "A256CBC-HS512":
                            return _symmetric512Key;
                        case "A256GCM":
                            return _symmetric256Key;
                    }
                    break;
            }

            throw new NotSupportedException();
        }


        public static IEnumerable<object[]> GetSupportedAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Direct };

#if SUPPORT_AESGCM
            yield return new object[] { EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128GcmKW };
            yield return new object[] { EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192GcmKW };
            yield return new object[] { EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256GcmKW };
            yield return new object[] { EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Direct };
#endif
        }
    }
}