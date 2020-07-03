using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using JsonWebToken.Internal;
using JsonWebToken.Tests.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class RsaJwkTests : JwkTestsBase
    {
        [Fact]
        public void RsaTest()
        {
            RsaJwk key = (RsaJwk)Jwk.FromJson("{\r\n  \"kty\": \"RSA\",\r\n  \"e\": \"AQAB\",\r\n  \"n\": \"80mC34wTp_AXmleVeOXYvk8iLFe87otu0KLdLE8C-YVvIWu0YQntuFbqU_8GUGEQTJBSe94tse5yTR-OrHN_omW5Hfy0M6oIQLnS6m2cm3WN8ToZVye7mM5AtD5jRtMMob_C84P1D2JpE4hf1JrXJFRkw4by1kXY0GI0-p5LhW82IWPnya5UXEoqIP4ZN9uB0K3q4KIb34phCU64FQlLUas6syipG-WTocM8z0OdlGwAYKlmJPlmSmjUrOAEkxBs9fq549q2d-Fs14i3Gw-1YQxeEl8ghNeG3BVWjJuKh_ZNJ5mrPRIMydVu4A0VYzgr6Zw1q3Wf4y2qddoL-aYrkQ\",\r\n  \"d\": \"V7CZcYYF17RcbY9AGxGNrBrN0HnXaYvsZ1ssqTnZcqK7yaoOnCN-AcGiOKBlYDd8LnyennMYuVee71l-jX4b9ScBMGPTeAPDccEI2uKjXg1jGh284IM7xPoirFUIZ5DOrsZ1uFxJyj_Ia_ftwq4E-d1JbIiJot4OJh4fxm2j_vXA9fZahkT5DLZeUEshWDDg8EuP3cTkY6WAsPnL9MoTfCInAuf05FvOj0lAt-IgwJkToEVZlXDrNe35UFPf0bTtTb5oQZZixTbH8Dbt19v75k7p7UlKx_--gyE_ZGt0YRg-REvrnsRW52t5UlA9X39-PSOl8CnEWutw1glNi8y0WQ\",\r\n  \"dp\": \"Qk6sHCAVBzPrdUU3fG8sSSjTXEV06hJVfAkydkkSXoSGBjqabqkWLztFggi_aDjsML18gvcsxLn74JxGcgq8nnNDvCb4OQ2y-p2n9FfjaZaRcZBSgfQu3JWVwmf3jPSJAVuJMoNs2IJEFkCIsfQz3cKxOGgL3r6LsTusLDg5Lg0\",\r\n  \"dq\": \"N-s6TyzgwBaQ2kr3r63P8O1YCAUnnridaxcA-OytM_J-L7Yxcs7ypcDLPYS2_cKh0KysCVxkvN-i2b8Z_LDh_-yBUPkQMCqn3MB_hPS1emI8xYPxFwGXrio7m9suklMQGBdSvGjDH6dDEVEjih8ZZyaltVzO7eWiRT-Zo-CHDmk\",\r\n  \"p\": \"9Kf5AcLZRuVRKUJWrGpRsk1gF2sL5e5LcR8Uxpn-5hHhMkCFbEpwmOlwsrGHWZ-c-rEB0pD9JRSednmwIP5Wb6srQkBYF2BdSLxw6OiPsB_AeGatgVJPDQG8B3Y97j6jLhmTh7Dks4NPIjmUDiMxhZX2_lFKyPL6JS0EWeJFrOc\",\r\n  \"q\": \"_pFJ8pzp0wh7NsR_p-U_f1jcCDN-Cqx-rce8kRCutWDY2JmpzqRoycnQ4aBWigXTPxDxGUJUz37SSZWDKWDJLCVLbM0pfb0jMwHarqFeO3XZTOe4NdKYW6aMhUcaWF-klPALu1mLoyU_9Pp3js58BWgmn84ADFDOwe-ewTrgnMc\",\r\n  \"qi\": \"qjCyZAXJd_ga3HWOli4Ceje3vnDv2wwqfs4AfT-HYou9M_G9AfLxx2CUsLL7P8Y2lEhU-L6vRiUyHqGz5EkD1DUSdnfqT0LAndcw2EnLooX1GcPqCbi-BwjxiPiF5z2flwjYQQQ3yodv-ToTDxy3b9hVq-W1lLPlfhrJIwcEBuo\"\r\n}");
            var parameters = key.ExportParameters();
            RSA rsa = RSA.Create();
            rsa.ImportParameters(parameters);

            var rsaKeyWrapper = new RsaKeyWrapper(key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaPkcs1);
            int keyWrapSize = rsaKeyWrapper.GetKeyWrapSize();
            Span<byte> wrappedKey = new byte[keyWrapSize];

            var cek = new SymmetricJwk("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");
            rsaKeyWrapper.WrapKey(cek, new JwtObject(), wrappedKey);
            var data = cek.AsSpan().ToArray();
            var rsaKeyUnwrapper = new RsaKeyUnwrapper(key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaPkcs1);
            var expectedData = new byte[cek.AsSpan().Length];

            var unwrapped = rsaKeyUnwrapper.TryUnwrapKey(wrappedKey, expectedData, new JwtHeader(), out int bytesWritten);

            Assert.Equal("F8F61435DBCB5D59DCF32250C3B89091294D9806F6D3664EFAB7C2CAB01CD4BA", data.ByteArrayToHex());
            Assert.Equal(data.Length, bytesWritten);
            Assert.Equal("F8F61435DBCB5D59DCF32250C3B89091294D9806F6D3664EFAB7C2CAB01CD4BA", expectedData.ByteArrayToHex());
            Assert.True(unwrapped);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            return base.CreateKeyWrapper_Succeed(key, enc, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureValidationKeys))]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override Signer CreateSigner_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSigner_Succeed(key, alg);
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
            Assert.False(key.SupportEncryption(enc));
            Assert.True(key.SupportKeyManagement(alg));
        }

        [Theory]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            Assert.True(key.SupportSignature(alg));
        }

        [Theory]
        [InlineData("{\"kty\":\"RSA\",\"kid\":\"juliet@capulet.lit\",\"use\":\"enc\",\"n\":\"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q\",\"e\":\"AQAB\",\"d\":\"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ\",\"p\":\"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws\",\"q\":\"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s\",\"dp\":\"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c\",\"dq\":\"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots\",\"qi\":\"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8\"}")]
        [InlineData("{\"kid\":\"juliet@capulet.lit\",\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q\",\"e\":\"AQAB\",\"d\":\"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ\",\"p\":\"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws\",\"q\":\"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s\",\"dp\":\"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c\",\"dq\":\"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots\",\"qi\":\"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8\"}")]
        [InlineData("{\"kty\":\"RSA\",\"kid\":\"juliet@capulet.lit\",\"use\":\"enc\",\"n\":\"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q\",\"e\":\"AQAB\",\"d\":\"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ\",\"p\":\"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws\",\"q\":\"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s\",\"dp\":\"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c\",\"dq\":\"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots\",\"qi\":\"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"true\":true,\"false\":false,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        [InlineData("{\"kid\":\"juliet@capulet.lit\",\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q\",\"e\":\"AQAB\",\"d\":\"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ\",\"p\":\"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws\",\"q\":\"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s\",\"dp\":\"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c\",\"dq\":\"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots\",\"qi\":\"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"true\":true,\"false\":false,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        public override void FromJson(string json)
        {
            // https://tools.ietf.org/html/rfc7517#appendix-C.1
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<RsaJwk>(key);

            Assert.Equal("juliet@capulet.lit", jwk.Kid);
            Assert.True(JwkUseNames.Enc.SequenceEqual(jwk.Use));

            Assert.Equal(jwk.N, Base64Url.Decode("t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));
            Assert.Equal(jwk.E, Base64Url.Decode("AQAB"));
            Assert.Equal(jwk.D, Base64Url.Decode("GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
            Assert.Equal(jwk.P, Base64Url.Decode("2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
            Assert.Equal(jwk.Q, Base64Url.Decode("1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
            Assert.Equal(jwk.DP, Base64Url.Decode("KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
            Assert.Equal(jwk.DQ, Base64Url.Decode("AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
            Assert.Equal(jwk.QI, Base64Url.Decode("lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));
        }

        [Theory]
        [InlineData("{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        [InlineData("{\"use\":\"sig\",\"kty\":\"RSA\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        public override void FromJson_WithProperties(string json)
        {
            // https://tools.ietf.org/html/rfc7517#appendix-B
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<RsaJwk>(key);

            Assert.NotNull(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X5c);

            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE"), jwk.X5t);
            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA"), jwk.X5tS256);
            Assert.Equal("sign", jwk.KeyOps[0]);
            Assert.Equal("https://example.com", jwk.X5u);
        }

        private const string Pkcs8PemRsaPrivateKey = @"
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtz9Z9e6L1V4kt/8C
mtFqhUPJbSU+VDGbk1MsQcPBR3uJ2y0vM9e5qHRYSOBqjmg7UERRHhvKNiUn4Xz0
KzgGFQIDAQABAkEAr+byNi+cr17FpJH4MCEiPXaKnmkH4c4U52EJtL9yg2gijBrp
Ykat3c2nWb0EGGi5aWgXxQHoi7z97/ACD4X3KQIhAPNyex6GdiBVlNPHOgInTU8a
mARKKVHIXM0SxvxXrRl7AiEAwLI66OpSqftDTv1KUfNe6+hyoh23ggzUSYiWuVT0
Ya8CHwiO/cUU9RIt8A2B84gf2ZfuV2nPMaSuZpTPFC/K5UsCIQCsJMzx1JuilQAN
acPiMCuFTnRSFYAhozpmsqoLyTREqwIhAMLJlZTGjEB2N+sEazH5ToEczQzKqp7t
9juGNbOPhoEL
-----END PRIVATE KEY-----";

        private const string Pkcs1PemRsaPrivateKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALc/WfXui9VeJLf/AprRaoVDyW0lPlQxm5NTLEHDwUd7idstLzPX
uah0WEjgao5oO1BEUR4byjYlJ+F89Cs4BhUCAwEAAQJBAK/m8jYvnK9exaSR+DAh
Ij12ip5pB+HOFOdhCbS/coNoIowa6WJGrd3Np1m9BBhouWloF8UB6Iu8/e/wAg+F
9ykCIQDzcnsehnYgVZTTxzoCJ01PGpgESilRyFzNEsb8V60ZewIhAMCyOujqUqn7
Q079SlHzXuvocqIdt4IM1EmIlrlU9GGvAh8Ijv3FFPUSLfANgfOIH9mX7ldpzzGk
rmaUzxQvyuVLAiEArCTM8dSbopUADWnD4jArhU50UhWAIaM6ZrKqC8k0RKsCIQDC
yZWUxoxAdjfrBGsx+U6BHM0Myqqe7fY7hjWzj4aBCw==
-----END RSA PRIVATE KEY-----";

        private const string Pkcs8PemRsaPublicKey = @"
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALc/WfXui9VeJLf/AprRaoVDyW0lPlQx
m5NTLEHDwUd7idstLzPXuah0WEjgao5oO1BEUR4byjYlJ+F89Cs4BhUCAwEAAQ==
-----END PUBLIC KEY-----";

        private const string Pkcs1PemRsaPublicKey = @"
-----BEGIN RSA PUBLIC KEY-----
MEgCQQC3P1n17ovVXiS3/wKa0WqFQ8ltJT5UMZuTUyxBw8FHe4nbLS8z17modFhI
4GqOaDtQRFEeG8o2JSfhfPQrOAYVAgMBAAE=
-----END RSA PUBLIC KEY-----";

        [Theory]
        [InlineData(Pkcs1PemRsaPrivateKey)]
        [InlineData(Pkcs8PemRsaPrivateKey)]
        public void FromPem_PrivateKey(string pem)
        {
            var key = RsaJwk.FromPem(pem);
            AssertKeyEquals(DiminishedDPParameters, key.ExportParameters());
            Assert.True(key.HasPrivateKey);
        }

        [Theory]
        [InlineData(Pkcs1PemRsaPublicKey)]
        [InlineData(Pkcs8PemRsaPublicKey)]
        public void FromPem_PublicKey(string pem)
        {
            var key = RsaJwk.FromPem(pem);
            AssertKeyEquals(ToPublic(DiminishedDPParameters), key.ExportParameters());
            Assert.False(key.HasPrivateKey);
        }

        [Fact]
        public void FromPem_UnexpectedKeyType_ThrowArgumentException()
        {
            string pem = @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcKEsLbFoRe1W/2jP
whpHKz8E19aFG/Y0ny19WzRSs4qhRANCAASBAezkdGSm6tcM9ppuK9PYhpGjJi0i
y6T3Y16v8maAqNihK6YdWZI19n2ctNWPF4PTykPnjwpauqYkB5k2wMOp
-----END PRIVATE KEY-----";
            Assert.Throws<InvalidOperationException>(() => RsaJwk.FromPem(pem));
        }

        private static void AssertKeyEquals(in RSAParameters expected, in RSAParameters actual)
        {
            Assert.Equal(expected.Modulus, actual.Modulus);
            Assert.Equal(expected.Exponent, actual.Exponent);

            Assert.Equal(expected.P, actual.P);
            Assert.Equal(expected.DP, actual.DP);
            Assert.Equal(expected.Q, actual.Q);
            Assert.Equal(expected.DQ, actual.DQ);
            Assert.Equal(expected.InverseQ, actual.InverseQ);

            if (expected.D == null)
            {
                Assert.Null(actual.D);
            }
            else
            {
                Assert.NotNull(actual.D);

                // If the value matched expected, take that as valid and shortcut the math.
                // If it didn't, we'll test that the value is at least legal.
                if (!expected.D.AsSpan().SequenceEqual(actual.D))
                {
                    VerifyDValue(actual);
                }
            }
        }

        private static void VerifyDValue(in RSAParameters rsaParams)
        {
            if (rsaParams.P == null)
            {
                return;
            }

            // Verify that the formula (D * E) % LCM(p - 1, q - 1) == 1
            // is true.
            //
            // This is NOT the same as saying D = ModInv(E, LCM(p - 1, q - 1)),
            // because D = ModInv(E, (p - 1) * (q - 1)) is a valid choice, but will
            // still work through this formula.
            BigInteger p = PositiveBigInteger(rsaParams.P);
            BigInteger q = PositiveBigInteger(rsaParams.Q);
            BigInteger e = PositiveBigInteger(rsaParams.Exponent);
            BigInteger d = PositiveBigInteger(rsaParams.D);

            BigInteger lambda = LeastCommonMultiple(p - 1, q - 1);

            BigInteger modProduct = (d * e) % lambda;
            Assert.Equal(BigInteger.One, modProduct);
        }

        private static BigInteger PositiveBigInteger(byte[] bigEndianBytes)
        {
            byte[] littleEndianBytes;

            if (bigEndianBytes[0] >= 0x80)
            {
                // Insert a padding 00 byte so the number is treated as positive.
                littleEndianBytes = new byte[bigEndianBytes.Length + 1];
                Buffer.BlockCopy(bigEndianBytes, 0, littleEndianBytes, 1, bigEndianBytes.Length);
            }
            else
            {
                littleEndianBytes = (byte[])bigEndianBytes.Clone();

            }

            Array.Reverse(littleEndianBytes);
            return new BigInteger(littleEndianBytes);
        }

        private static BigInteger LeastCommonMultiple(BigInteger a, BigInteger b)
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(a, b);
            return BigInteger.Abs(a) / gcd * BigInteger.Abs(b);
        }

        private static RSAParameters ToPublic(RSAParameters rsaParams)
        {
            return new RSAParameters
            {
                Exponent = rsaParams.Exponent,
                Modulus = rsaParams.Modulus
            };
        }

        public static readonly RSAParameters DiminishedDPParameters = new RSAParameters
        {
            Modulus = new byte[]
            {
                0xB7, 0x3F, 0x59, 0xF5, 0xEE, 0x8B, 0xD5, 0x5E,
                0x24, 0xB7, 0xFF, 0x02, 0x9A, 0xD1, 0x6A, 0x85,
                0x43, 0xC9, 0x6D, 0x25, 0x3E, 0x54, 0x31, 0x9B,
                0x93, 0x53, 0x2C, 0x41, 0xC3, 0xC1, 0x47, 0x7B,
                0x89, 0xDB, 0x2D, 0x2F, 0x33, 0xD7, 0xB9, 0xA8,
                0x74, 0x58, 0x48, 0xE0, 0x6A, 0x8E, 0x68, 0x3B,
                0x50, 0x44, 0x51, 0x1E, 0x1B, 0xCA, 0x36, 0x25,
                0x27, 0xE1, 0x7C, 0xF4, 0x2B, 0x38, 0x06, 0x15,
            },
            Exponent = new byte[]
            {
                0x01, 0x00, 0x01,
            },
            D = new byte[]
            {
                0xAF, 0xE6, 0xF2, 0x36, 0x2F, 0x9C, 0xAF, 0x5E,
                0xC5, 0xA4, 0x91, 0xF8, 0x30, 0x21, 0x22, 0x3D,
                0x76, 0x8A, 0x9E, 0x69, 0x07, 0xE1, 0xCE, 0x14,
                0xE7, 0x61, 0x09, 0xB4, 0xBF, 0x72, 0x83, 0x68,
                0x22, 0x8C, 0x1A, 0xE9, 0x62, 0x46, 0xAD, 0xDD,
                0xCD, 0xA7, 0x59, 0xBD, 0x04, 0x18, 0x68, 0xB9,
                0x69, 0x68, 0x17, 0xC5, 0x01, 0xE8, 0x8B, 0xBC,
                0xFD, 0xEF, 0xF0, 0x02, 0x0F, 0x85, 0xF7, 0x29,
            },
            P = new byte[]
            {
                0xF3, 0x72, 0x7B, 0x1E, 0x86, 0x76, 0x20, 0x55,
                0x94, 0xD3, 0xC7, 0x3A, 0x02, 0x27, 0x4D, 0x4F,
                0x1A, 0x98, 0x04, 0x4A, 0x29, 0x51, 0xC8, 0x5C,
                0xCD, 0x12, 0xC6, 0xFC, 0x57, 0xAD, 0x19, 0x7B,
            },
            DP = new byte[]
            {
                // Note the leading 0x00 byte.
                0x00, 0x08, 0x8E, 0xFD, 0xC5, 0x14, 0xF5, 0x12,
                0x2D, 0xF0, 0x0D, 0x81, 0xF3, 0x88, 0x1F, 0xD9,
                0x97, 0xEE, 0x57, 0x69, 0xCF, 0x31, 0xA4, 0xAE,
                0x66, 0x94, 0xCF, 0x14, 0x2F, 0xCA, 0xE5, 0x4B,
            },
            Q = new byte[]
            {
                0xC0, 0xB2, 0x3A, 0xE8, 0xEA, 0x52, 0xA9, 0xFB,
                0x43, 0x4E, 0xFD, 0x4A, 0x51, 0xF3, 0x5E, 0xEB,
                0xE8, 0x72, 0xA2, 0x1D, 0xB7, 0x82, 0x0C, 0xD4,
                0x49, 0x88, 0x96, 0xB9, 0x54, 0xF4, 0x61, 0xAF,
            },
            DQ = new byte[]
            {
                0xAC, 0x24, 0xCC, 0xF1, 0xD4, 0x9B, 0xA2, 0x95,
                0x00, 0x0D, 0x69, 0xC3, 0xE2, 0x30, 0x2B, 0x85,
                0x4E, 0x74, 0x52, 0x15, 0x80, 0x21, 0xA3, 0x3A,
                0x66, 0xB2, 0xAA, 0x0B, 0xC9, 0x34, 0x44, 0xAB,
            },
            InverseQ = new byte[]
            {
                0xC2, 0xC9, 0x95, 0x94, 0xC6, 0x8C, 0x40, 0x76,
                0x37, 0xEB, 0x04, 0x6B, 0x31, 0xF9, 0x4E, 0x81,
                0x1C, 0xCD, 0x0C, 0xCA, 0xAA, 0x9E, 0xED, 0xF6,
                0x3B, 0x86, 0x35, 0xB3, 0x8F, 0x86, 0x81, 0x0B,
            }
        };



        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { PrivateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaPkcs1 };
            yield return new object[] { PrivateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep };
#if !NET461 && !NET47
            yield return new object[] { PrivateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep256 };
            yield return new object[] { PrivateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep384 };
            yield return new object[] { PrivateRsa2048Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.RsaOaep512 };
#endif
        }

        public static IEnumerable<object[]> GetSignatureValidationKeys()
        {
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSha256 };
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSha384 };
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSha512 };
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha256 };
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha384 };
            yield return new object[] { PublicRsa2048Key, SignatureAlgorithm.RsaSsaPssSha512 };
        }

        public static IEnumerable<object[]> GetSignatureCreationKeys()
        {
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSha256 };
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSha384 };
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSha512 };
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha256 };
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha384 };
            yield return new object[] { PrivateRsa2048Key, SignatureAlgorithm.RsaSsaPssSha512 };
        }

        [Fact]
        public override void WriteTo()
        {
            var key = RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSha256.Utf8Name);
            key.Kid = "kid-rsa";
            key.KeyOps.Add("sign");
            key.Use = JwkUseNames.Sig.ToArray();
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using var bufferWriter = new PooledByteBufferWriter();
            key.Serialize(bufferWriter);
            var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());

            Assert.Contains("\"kid\":\"kid-rsa\"", json);
            Assert.Contains("\"key_ops\":[\"sign\"]", json);
            Assert.Contains("\"use\":\"sig\"", json);
            Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
            Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\"", json);
#if NETSTANDARD2_0
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com") + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==") + "\"]", json);
#else
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com", Constants.JsonEncoder) + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==", Constants.JsonEncoder) + "\"]", json);
#endif

            Assert.Contains("\"e\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.E)) + "\"", json);
            Assert.Contains("\"n\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.N)) + "\"", json);
            Assert.Contains("\"d\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.D)) + "\"", json);

            Assert.Contains("\"dp\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.DP)) + "\"", json);
            Assert.Contains("\"dq\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.DQ)) + "\"", json);
            Assert.Contains("\"p\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.P)) + "\"", json);
            Assert.Contains("\"q\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.Q)) + "\"", json);
            Assert.Contains("\"qi\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.QI)) + "\"", json);
        }

        private static RsaJwk PrivateRsa2048Key => new RsaJwk
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

        private static RsaJwk PublicRsa2048Key => new RsaJwk
        (
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB"
        );
    }
}
