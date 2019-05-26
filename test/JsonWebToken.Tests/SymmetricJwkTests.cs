using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SymmetricJwkTests : JwkTestsBase
    {
        [Theory]
        [MemberData(nameof(GetEncryptionKeys))]
        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor_Succeed(Jwk key, EncryptionAlgorithm enc)
        {
            return base.CreateAuthenticatedEncryptor_Succeed(key, enc);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            return base.CreateKeyWrapper_Succeed(key, enc, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureValidationKeys))]
        public override Signer CreateSignerForValidation_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSignerForValidation_Succeed(key, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override Signer CreateSignerForSignature_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSignerForSignature_Succeed(key, alg);
        }

        [Fact]
        public override void Canonicalize()
        {
            var jwk = SymmetricJwk.GenerateKey(256);
            var canonicalizedKey = (SymmetricJwk)CanonicalizeKey(jwk);
            Assert.NotEqual(0, canonicalizedKey.K.Length);
        }

        [Theory]
        [MemberData(nameof(GetEncryptionKeys))]
        public override void IsSupportedEncryption_Success(Jwk key, EncryptionAlgorithm enc)
        {
            base.IsSupportedEncryption_Success(key, enc);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Assert.True(key.IsSupported(alg));
        }

        [Theory]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            Assert.True(key.IsSupported(alg));
        }

        public static IEnumerable<object[]> GetEncryptionKeys()
        {
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes128CbcHmacSha256 };
            yield return new object[] { _symmetric384Key, EncryptionAlgorithm.Aes192CbcHmacSha384 };
            yield return new object[] { _symmetric512Key, EncryptionAlgorithm.Aes256CbcHmacSha512 };
#if NETCOREAPP3_0
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes128Gcm };
            yield return new object[] { _symmetric384Key, EncryptionAlgorithm.Aes192Gcm };
            yield return new object[] { _symmetric512Key, EncryptionAlgorithm.Aes256Gcm };
#endif
        }

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW };
#if NETCOREAPP3_0
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128GcmKW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192GcmKW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256GcmKW };
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256KW };
#endif
        }

        public static IEnumerable<object[]> GetSignatureValidationKeys()
        {
            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha256 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha384 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha512 };
        }

        public static IEnumerable<object[]> GetSignatureCreationKeys()
        {
            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha256 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha384 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha512 };
        }

        [Theory]
        [InlineData("{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"}")]
        [InlineData("{\"alg\":\"A128KW\",\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"}")]
        public override void FromJson(string json)
        {
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<SymmetricJwk>(key);

            Assert.Equal(KeyManagementAlgorithm.Aes128KW.Utf8Name, jwk.Alg);
            Assert.Equal("kid1", jwk.Kid);
            Assert.True(jwk.K.SequenceEqual(Base64Url.Decode("GawgguFyGrWKav7AX4VKUg")));
        }

        private static readonly SymmetricJwk _symmetric128Key = new SymmetricJwk("LxOcGxlu169Vxa1A7HyelQ");

        private static readonly SymmetricJwk _symmetric192Key = new SymmetricJwk("kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc"
        );

        private static readonly SymmetricJwk _symmetric256Key = new SymmetricJwk("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");

        private static readonly SymmetricJwk _symmetric384Key = new SymmetricJwk("V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm");

        private static readonly SymmetricJwk _symmetric512Key = new SymmetricJwk("98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg");
    }
}
