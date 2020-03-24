using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{

    [Config(typeof(DefaultCoreConfig))]
    public class ValidateCompressedToken : ValidateToken
    {
        private static byte[] encryptionKey = Tokens.EncryptionKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwt(token);
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
        public override Microsoft.IdentityModel.Tokens.TokenValidationResult WilsonJwt(BenchmarkToken token)
        {
            return WilsonJwtCore(token.TokenString, wilsonParameters);
        }

        public override Dictionary<string, object> jose_jwt(BenchmarkToken token)
        {
            throw new NotImplementedException();
        }

        public override IDictionary<string, object> Jwt_Net(BenchmarkToken token)
        {
            throw new NotImplementedException();
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWE DEF " + (i == 0 ? "" : i.ToString()) + "6 claims";
            }
        }
    }
}
