using System;
using System.Collections.Generic;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweSymmetricTokenTests
    {
        private readonly SymmetricJwk _symmetric128Key = SymmetricJwk.FromBase64Url("LxOcGxlu169Vxa1A7HyelQ");

        private readonly SymmetricJwk _symmetric192Key = SymmetricJwk.FromBase64Url("kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc");

        private readonly SymmetricJwk _symmetric256Key = SymmetricJwk.FromBase64Url("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");

        private readonly SymmetricJwk _symmetric384Key = SymmetricJwk.FromBase64Url("V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm");

        private readonly SymmetricJwk _symmetric512Key = SymmetricJwk.FromBase64Url("98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg");

        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

        [Fact]
        public void Encode_Decode_NotSupported()
        {
            var writer = new JwtWriter();

            var descriptor = new JweDescriptor(Jwk.None, KeyManagementAlgorithm.Dir, new EncryptionAlgorithm(AlgorithmId.Undefined, "unsupported", 0, SignatureAlgorithm.None, 0, EncryptionType.NotSupported))
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HS256)
                {
                    Payload = new JwtPayload
                    {
                        { "sub", "Alice" }
                    }
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
            var encryptionKey = SelectKey(enc.Name.ToString(), alg.Name.ToString());

            var descriptor = new JweDescriptor(encryptionKey, alg, enc)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HS256)
                {
                    Payload = new JwtPayload
                    {
                        { "sub", "Alice" }
                    }
                }
            };

            var token = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .RequireSignatureByDefault(_signingKey)
                .WithDecryptionKey(encryptionKey)
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);

            Assert.True(jwt.Payload.TryGetClaim("sub", out var sub));
            Assert.Equal("Alice", sub.GetString());
            jwt.Dispose();
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
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.Dir };

#if SUPPORT_AESGCM
            yield return new object[] { EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.A128GcmKW };
            yield return new object[] { EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.A192GcmKW };
            yield return new object[] { EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.A256GcmKW };
            yield return new object[] { EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.Dir };
#endif
        }
    }
}