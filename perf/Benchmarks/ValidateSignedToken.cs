using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ValidateSignedToken : ValidateToken
    {
        private static byte[] signingKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwt(token);
            jose_jwt(token);
            Jwt_Net(token);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override TokenValidationResult JsonWebToken(BenchmarkToken token)
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
        public override Dictionary<string, object> jose_jwt(BenchmarkToken token)
        {
            return JoseDotNetCore(token.TokenString, Jose.JwsAlgorithm.HS256, signingKey);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override IDictionary<string, object> Jwt_Net(BenchmarkToken token)
        {
            return JwtDotNetCore(token.TokenString, signingKey, true);
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS " + (i == 0 ? "" : i.ToString()) + "6 claims";
            }
        }
    }
}
