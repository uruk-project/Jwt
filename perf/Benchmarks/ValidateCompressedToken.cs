using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{

    [Config(typeof(DefaultCoreConfig))]
    public class ValidateCompressedToken : ValidateToken
    {
        private static readonly byte[] encryptionKey = Tokens.EncryptionKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwtAsync(token).Wait();
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
                yield return "JWE DEF " + i + "6 claims";
            }
        }
    }
}
