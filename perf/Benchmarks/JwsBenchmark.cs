using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    public class JwsBenchmark : JwtBenchmarkBase
    {
        public IEnumerable<string> GetTokens()
        {
            yield return "JWS-empty";
            yield return "JWS-small";
            yield return "JWS-medium";
            yield return "JWS-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void ValidateJwt(string token)
        {
            ValidateJwtCore(token, policyWithSignatureValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override void WriteJwt(string token)
        {
            WriteJwtCore(token);
        }
    }
}