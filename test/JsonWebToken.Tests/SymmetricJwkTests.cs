using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SymmetricJwkTests : JwkTests
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

        private static readonly SymmetricJwk _symmetric128Key = new SymmetricJwk("LxOcGxlu169Vxa1A7HyelQ");

        private static readonly SymmetricJwk _symmetric192Key = new SymmetricJwk("kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc"
        );

        private static readonly SymmetricJwk _symmetric256Key = new SymmetricJwk("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");

        private static readonly SymmetricJwk _symmetric384Key = new SymmetricJwk("V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm");

        private static readonly SymmetricJwk _symmetric512Key = new SymmetricJwk("98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg");

        private static readonly RsaJwk _privateRsa2048Key = new RsaJwk
        (
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB",
            d: "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            p: "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            q: "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            dp: "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            dq: "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
            qi: "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
        );

        private static readonly RsaJwk _publicRsa2048Key = new RsaJwk
        (
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB"
        );

        private static readonly ECJwk _privateEcc256Key = new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );

        private static readonly ECJwk _publicEcc256Key = new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        private static readonly ECJwk _publicEcc384Key = new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static readonly ECJwk _privateEcc384Key = new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static readonly ECJwk _privateEcc512Key = new ECJwk
        (
            crv: EllipticalCurve.P521,
            d: "Adri8PbGJBWN5upp_67cKF8E0ADCF-w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HISTMh_RSmFFhTfBH",
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );

        private static readonly ECJwk _publicEcc512Key = new ECJwk
        (
            crv: EllipticalCurve.P521,
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );
    }
}
