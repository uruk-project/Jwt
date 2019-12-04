using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateEncryptedToken : ValidateToken
    {
        [GlobalSetup]
        public void Setup()
        {
            Jwt("JWE-empty");
            Wilson("JWE-empty");
            WilsonJwt("JWE-empty");
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
            //yield return "JWE-empty";
            yield return "JWE-small";
            yield return "JWE-medium";
            //yield return "JWE-big";
        }
    }
}
