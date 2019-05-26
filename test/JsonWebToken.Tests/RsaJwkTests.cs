﻿using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class RsaJwkTests : JwkTests
    {
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
            var jwk = RsaJwk.GenerateKey(2048, true);
            var canonicalizedKey = (RsaJwk)CanonicalizeKey(jwk);
            Assert.NotNull(canonicalizedKey.E);
            Assert.NotEmpty(canonicalizedKey.E);
            Assert.NotNull(canonicalizedKey.N);
            Assert.NotEmpty(canonicalizedKey.N);

            Assert.Null(canonicalizedKey.DP);
            Assert.Null(canonicalizedKey.DQ);
            Assert.Null(canonicalizedKey.D);
            Assert.Null(canonicalizedKey.P);
            Assert.Null(canonicalizedKey.Q);
            Assert.Null(canonicalizedKey.QI);
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

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { _privateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep };
            yield return new object[] { _privateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep256 };
            yield return new object[] { _privateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep384 };
            yield return new object[] { _privateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep512 };
            yield return new object[] { _privateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaPkcs1 };
        }

        public static IEnumerable<object[]> GetSignatureValidationKeys()
        {
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSha256 };
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSha384 };
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSha512 };
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha256 };
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha384 };
            yield return new object[] { _publicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha512 };
        }

        public static IEnumerable<object[]> GetSignatureCreationKeys()
        {
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSha256 };
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSha384 };
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSha512 };
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha256 };
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha384 };
            yield return new object[] { _privateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha512 };
        }

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
    }
}
