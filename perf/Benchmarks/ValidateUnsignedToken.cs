using System;
using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateUnsignedToken : ValidateToken
    {
        private static byte[] signingKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            Jwt("JWT-empty");
            Wilson("JWT-empty");
            WilsonJwt("JWT-empty");
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult Jwt(string token)
        {
            return JwtCore(token, token.Contains("empty") ? TokenValidationPolicy.NoValidation : tokenValidationPolicyWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override ClaimsPrincipal Wilson(string token)
        {
            return WilsonCore(token, token.Contains("empty") ? wilsonParametersWithoutValidation : wilsonParametersWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token)
        {
            return WilsonJwtCore(token, token.Contains("empty") ? wilsonParametersWithoutValidation : wilsonParametersWithoutSignature);
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWT-empty";
            for (int i = 0; i < 10; i++)
            {
                yield return "JWT-" + i;
            }

            //yield return "JWT-empty";
            //yield return "JWT-small";
            //yield return "JWT-medium";
            //yield return "JWT-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void JoseDotNet(string token)
        {
            JoseDotNetCore(token, Jose.JwsAlgorithm.none, signingKey);
        }

        public override void JwtDotNet(string token)
        {
            throw new NotSupportedException();
        }
    }
}
