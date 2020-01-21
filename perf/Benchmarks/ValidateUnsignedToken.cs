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
            Jwt(new BenchmarkToken("JWT-0"));
            Wilson(new BenchmarkToken("JWT-0"));
            WilsonJwt(new BenchmarkToken("JWT-0"));
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override TokenValidationResult Jwt(BenchmarkToken token)
        {
            return JwtCore(token.TokenBinary, tokenValidationPolicyWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override ClaimsPrincipal Wilson(BenchmarkToken token)
        {
            return WilsonCore(token.TokenString, wilsonParametersWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(BenchmarkToken token)
        {
            return WilsonJwtCore(token.TokenString, wilsonParametersWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override void JoseDotNet(BenchmarkToken token)
        {
            JoseDotNetCore(token.TokenString, Jose.JwsAlgorithm.none, signingKey);
        }

        public override void JwtDotNet(BenchmarkToken token)
        {
            throw new NotSupportedException();
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWT-" + i;
            }
        }
    }
}
