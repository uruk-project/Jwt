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
            Jwt(new BenchmarkToken("JWE-0"));
            Wilson(new BenchmarkToken("JWE-0"));
            WilsonJwt(new BenchmarkToken("JWE-0"));
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override TokenValidationResult Jwt(BenchmarkToken token)
        {
            return JwtCore(token.TokenBinary, tokenValidationPolicy);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override ClaimsPrincipal Wilson(BenchmarkToken token)
        {
            return WilsonCore(token.TokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(BenchmarkToken token)
        {
            return WilsonJwtCore(token.TokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override void JoseDotNet(BenchmarkToken token)
        {
            JoseDotNetCore(token.TokenString, Jose.JweEncryption.A128CBC_HS256, Jose.JweAlgorithm.A128KW, encryptionKey);
        }

        public override void JwtDotNet(BenchmarkToken token)
        {
            throw new NotImplementedException();
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWE-" + i;
            }
        }
    }
}
