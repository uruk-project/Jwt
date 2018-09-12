using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweSymmetricTokenTests
    {
        private readonly SymmetricJwk _symmetric128Key = new SymmetricJwk
        {
            K = "LxOcGxlu169Vxa1A7HyelQ"
        };

        private readonly SymmetricJwk _symmetric192Key = new SymmetricJwk
        {
            K = "kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc"
        };

        private readonly SymmetricJwk _symmetric256Key = new SymmetricJwk
        {
            K = "-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo"
        };

        private readonly SymmetricJwk _symmetric384Key = new SymmetricJwk
        {
            K = "V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm"
        };

        private readonly SymmetricJwk _symmetric512Key = new SymmetricJwk
        {
            K = "98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg"
        };

        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256.Name);

        [Theory]
        [MemberData(nameof(GetNotSupportedAlgorithms))]
        public void Encode_Decode_NotSuppoted(string enc, string alg)
        {
            var writer = new JsonWebTokenWriter();
            var encryptionKey = SelectKey(enc, alg);

            var descriptor = new JweDescriptor
            {
                Key = encryptionKey,
                EncryptionAlgorithm = (EncryptionAlgorithm)enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256.Name,
                    Subject = "Alice"
                }
            };

            Assert.Throws<NotSupportedException>(() =>
            {
                var token = writer.WriteToken(descriptor);
            });

            //var reader = new JsonWebTokenReader(encryptionKey);
            //var policy = new TokenValidationPolicyBuilder()
            //    .RequireSignature(_signingKey)
            //    .Build();

            //var result = reader.TryReadToken(token, policy);
            //Assert.Equal(TokenValidationStatus.Success, result.Status);
            //Assert.Equal("Alice", result.Token.Subject);
        }

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithms))]
        public void Encode_Decode(string enc, string alg)
        {
            var writer = new JsonWebTokenWriter();
            var encryptionKey = SelectKey(enc, alg);

            var descriptor = new JweDescriptor
            {
                Key = encryptionKey,
                EncryptionAlgorithm = (EncryptionAlgorithm)enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256.Name,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(encryptionKey);
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
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
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes128KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes192KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes256KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Direct.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes128KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes192KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes256KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Direct.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes128KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes192KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes256KW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Direct.Name };

            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes128GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes192GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256.Name, KeyManagementAlgorithm.Aes256GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes128GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes192GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384.Name, KeyManagementAlgorithm.Aes256GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes128GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes192GcmKW.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512.Name, KeyManagementAlgorithm.Aes256GcmKW.Name };
        }

        public static IEnumerable<object[]> GetNotSupportedAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128Gcm.Name, KeyManagementAlgorithm.Direct.Name };
            yield return new object[] { EncryptionAlgorithm.Aes192Gcm.Name, KeyManagementAlgorithm.Direct.Name };
            yield return new object[] { EncryptionAlgorithm.Aes256Gcm.Name, KeyManagementAlgorithm.Direct.Name };
        }

    }
}