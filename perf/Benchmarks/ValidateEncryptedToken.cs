using System;
using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateEncryptedToken : ValidateToken
    {
        private static byte[] encryptionKey = Tokens.EncryptionKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            Jwt("JWE-empty");
            Wilson("JWE-empty");
            WilsonJwt("JWE-empty");
            JoseDotNet("JWE-empty");
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult Jwt(string token)
        {
            return JwtCore(token, token.Contains("empty") ? TokenValidationPolicy.NoValidation : tokenValidationPolicy);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override ClaimsPrincipal Wilson(string token)
        {
            return WilsonCore(token, token.Contains("empty") ? wilsonParametersWithoutValidation : wilsonParameters);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token)
        {
            return WilsonJwtCore(token, token.Contains("empty") ? wilsonParametersWithoutValidation : wilsonParameters);
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWE-empty";
            for (int i = 0; i < 10; i++)
            {
                yield return "JWE-" + i;
            }

            //yield return "JWE-empty";
            //yield return "JWE-small";
            //yield return "JWE-medium";
            //yield return "JWE-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void JoseDotNet(string token)
        {
            JoseDotNetCore(token, Jose.JweEncryption.A128CBC_HS256, Jose.JweAlgorithm.A128KW, encryptionKey);
        }

        public override void JwtDotNet(string token)
        {
            throw new NotImplementedException();
        }
    }
}
