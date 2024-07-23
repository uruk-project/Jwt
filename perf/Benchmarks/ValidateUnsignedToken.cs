using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ValidateUnsignedToken : ValidateToken
    {
        private static readonly byte[] signingKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwtAsync(token).Wait();
            jose_jwt(token);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Jwt JsonWebToken(BenchmarkToken token)
        {
            JwtCore(token.TokenBinary, tokenValidationPolicyWithoutSignature, out var jwt);
            jwt.Dispose();
            return jwt;
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override ClaimsPrincipal Wilson(BenchmarkToken token)
        {
            return WilsonCore(token.TokenString, wilsonParametersWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override async Task<Microsoft.IdentityModel.Tokens.TokenValidationResult> WilsonJwtAsync(BenchmarkToken token)
        {
            return await WilsonJwtCoreAsync(token.TokenString, wilsonParametersWithoutSignature);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Dictionary<string, object> jose_jwt(BenchmarkToken token)
        {
            return JoseDotNetCore(token.TokenString, Jose.JwsAlgorithm.none, null);
        }

        public override IDictionary<string, object> Jwt_Net(BenchmarkToken token)
        {
            throw new NotSupportedException();
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWT " + i + "6 claims";
            }
        }
    }
}
