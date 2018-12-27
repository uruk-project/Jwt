using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwsTokenTests
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

        private readonly RsaJwk _privateRsa2048Key = new RsaJwk
        {
            N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            E = "AQAB",
            D = "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            P = "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            Q = "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            DP = "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            DQ = "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
            QI = "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
        };

        private readonly RsaJwk _publicRsa2048Key = new RsaJwk
        {
            N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            E = "AQAB",
        };

        private readonly ECJwk _privateEcc256Key = new ECJwk
        {
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        };

        private readonly ECJwk _publicEcc256Key = new ECJwk
        {
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        };

        private readonly ECJwk _publicEcc384Key = new ECJwk
        {
            Crv = "P-384",
            D = "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            X = "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            Y = "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        };

        private readonly ECJwk _privateEcc384Key = new ECJwk
        {
            Crv = "P-384",
            D = "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            X = "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            Y = "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        };

        private readonly ECJwk _privateEcc512Key = new ECJwk
        {
            Crv = "P-521",
            D = "Adri8PbGJBWN5upp_67cKF8E0ADCF-w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HISTMh_RSmFFhTfBH",
            X = "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            Y = "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        };

        private readonly ECJwk _publicEcc512Key = new ECJwk
        {
            Crv = "P-521",
            X = "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            Y = "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        };

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithm))]
        public void Encode_Decode(string alg)
        {
            var (signingKey, validationKey) = SelectKeys(alg);
            var writer = new JwtWriter();
            var descriptor = new JwsDescriptor
            {
                Key = signingKey,
                Algorithm = alg,
                Subject = "Alice"
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JwtReader();
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(validationKey, alg)
                .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
        }

        public static IEnumerable<object[]> GetSupportedAlgorithm()
        {
            yield return new object[] { (string)SignatureAlgorithm.HmacSha256 };
            yield return new object[] { (string)SignatureAlgorithm.HmacSha384 };
            yield return new object[] { (string)SignatureAlgorithm.HmacSha512 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSha256 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSha384 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSha512 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSsaPssSha256 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSsaPssSha384 };
            yield return new object[] { (string)SignatureAlgorithm.RsaSsaPssSha512 };
            yield return new object[] { (string)SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { (string)SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { (string)SignatureAlgorithm.EcdsaSha512 };
        }

        private (Jwk, Jwk) SelectKeys(string alg)
        {
            switch (alg)
            {
                case "HS256":
                    return (_symmetric128Key, _symmetric128Key);
                case "HS384":
                    return (_symmetric128Key, _symmetric128Key);
                case "HS512":
                    return (_symmetric128Key, _symmetric128Key);

                case "RS256":
                    return (_privateRsa2048Key, _publicRsa2048Key);
                case "RS384":
                    return (_privateRsa2048Key, _publicRsa2048Key);
                case "RS512":
                    return (_privateRsa2048Key, _publicRsa2048Key);

                case "PS256":
                    return (_privateRsa2048Key, _publicRsa2048Key);
                case "PS384":
                    return (_privateRsa2048Key, _publicRsa2048Key);
                case "PS512":
                    return (_privateRsa2048Key, _publicRsa2048Key);

                case "ES256":
                    return (_privateEcc256Key, _publicEcc256Key);
                case "ES384":
                    return (_privateEcc384Key, _publicEcc384Key);
                case "ES512":
                    return (_privateEcc512Key, _publicEcc512Key);
            }

            throw new NotSupportedException();
        }
    }
}