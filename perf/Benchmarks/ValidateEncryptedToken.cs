﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ValidateEncryptedToken : ValidateToken
    {
        private static readonly byte[] encryptionKey = Tokens.EncryptionKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwtAsync(token).Wait();
            //jose_jwt(token); // jose_jwt seems to not works 
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Jwt JsonWebToken(BenchmarkToken token)
        {
            JwtCore(token.TokenBinary, tokenValidationPolicy, out var jwt);
            jwt.Dispose();
            return jwt;
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override ClaimsPrincipal Wilson(BenchmarkToken token)
        {
            return WilsonCore(token.TokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override async Task<Microsoft.IdentityModel.Tokens.TokenValidationResult> WilsonJwtAsync(BenchmarkToken token)
        {
            return await WilsonJwtCoreAsync(token.TokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Dictionary<string, object> jose_jwt(BenchmarkToken token)
        {
            return new Dictionary<string, object>();
            //return JoseDotNetCore(token.TokenString, Jose.JweEncryption.A128CBC_HS256, Jose.JweAlgorithm.A128KW, encryptionKey);
        }

        public override IDictionary<string, object> Jwt_Net(BenchmarkToken token)
        {
            throw new NotImplementedException();
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWE " + i + "6 claims";
            }
        }
    }
}
