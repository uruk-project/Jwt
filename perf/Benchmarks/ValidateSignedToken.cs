using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateSignedToken : ValidateToken
    {
        private static byte[] signingKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            Jwt(new BenchmarkToken("JWS-0"));
            Wilson(new BenchmarkToken("JWS-0"));
            WilsonJwt(new BenchmarkToken("JWS-0"));
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
        public override Dictionary<string, object> JoseDotNet(BenchmarkToken token)
        {
            return JoseDotNetCore(token.TokenString, Jose.JwsAlgorithm.HS256, signingKey);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override IDictionary<string, object> JwtDotNet(BenchmarkToken token)
        {
            return JwtDotNetCore(token.TokenString, signingKey, true);
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS-" + i;
            }
        }
    }
}
