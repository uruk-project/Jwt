using BenchmarkDotNet.Attributes;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateUnsignedToken : ValidateToken
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult Jwt(string token)
        {
            return JwtCore(token, TokenValidationPolicy.NoValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override ClaimsPrincipal Wilson(string token)
        {
            return WilsonCore(token, wilsonParametersWithouSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token)
        {
            return WilsonJwtCore(token, wilsonParametersWithouSignature);
        }

        public IEnumerable<string> GetTokens()
        {
            //yield return "JWT-empty";
            yield return "JWT-small";
            yield return "JWT-medium";
            //yield return "JWT-big";
        }
    }
}
