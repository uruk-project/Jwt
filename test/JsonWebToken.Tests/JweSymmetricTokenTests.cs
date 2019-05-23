using System;
using System.Collections.Generic;
using System.Text;
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
                EncryptionAlgorithm = new EncryptionAlgorithm(-99, "unsupported", 0, SignatureAlgorithm.None, 0, EncryptionType.Undefined),
                Algorithm = KeyManagementAlgorithm.Direct,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
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
            var encryptionKey = SelectKey(enc, alg);

            var descriptor = new JweDescriptor
            {
                Key = encryptionKey,
                EncryptionAlgorithm = enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JwtReader(encryptionKey);
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
        }

        private SymmetricJwk SelectKey(string enc, byte[] alg)
        {
            switch (Encoding.UTF8.GetString(alg))
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
                        case "A128GCM":
                            return _symmetric256Key;
                        case "A192CBC-HS384":
                        case "A192GCM":
                            return _symmetric384Key;
                        case "A256CBC-HS512":
                        case "A256GCM":
                            return _symmetric512Key;
                    }
                    break;
            }

            throw new NotSupportedException();
        }


        public static IEnumerable<object[]> GetSupportedAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes192KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes128KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes256KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Direct.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes128KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes192KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Direct.Utf8Name };

            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes192GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes128GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes256GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes128GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes192GcmKW.Utf8Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256GcmKW.Utf8Name };
        }
    }
}