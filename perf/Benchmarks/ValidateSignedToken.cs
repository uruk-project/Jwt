using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateSignedToken : ValidateToken
    {
        [GlobalSetup]
        public void Setup()
        {
            Jwt("JWS-empty");
            Wilson("JWS-empty");
            WilsonJwt("JWS-empty");
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult Jwt(string token)
        {
            return JwtCore(token, policyWithSignatureValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override ClaimsPrincipal Wilson(string token)
        {
            return WilsonCore(token, wilsonParameters);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token)
        {
            return WilsonJwtCore(token, wilsonParameters);
        }

        public IEnumerable<string> GetTokens()
        {
            //yield return "JWS-empty";
            yield return "JWS-small";
            yield return "JWS-medium";
            //yield return "JWS-big";
        }
    }
}
