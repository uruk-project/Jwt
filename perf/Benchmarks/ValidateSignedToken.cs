﻿using System.Collections.Generic;
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
            Jwt("JWS-empty");
            Wilson("JWS-empty");
            WilsonJwt("JWS-empty");
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

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(string token)
        {
            return WilsonJwtCore(token, token.Contains("empty") ? wilsonParametersWithoutValidation : wilsonParameters);
        }

        public IEnumerable<string> GetTokens()
        {
            yield return "JWS-empty";
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS-" + i;
            }

            //yield return "JWS-small";
            //yield return "JWS-medium";
            //yield return "JWS-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void JoseDotNet(string token)
        {
            JoseDotNetCore(token, Jose.JwsAlgorithm.HS256, signingKey);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void JwtDotNet(string token)
        {
            JwtDotNetCore(token, signingKey, true);
        }
    }
}
