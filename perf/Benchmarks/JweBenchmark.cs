using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    public class JweBenchmark : JwtBenchmarkBase
    {
        public IEnumerable<string> GetTokens()
        {
            yield return "JWE-empty";
            yield return "JWE-small";
            yield return "JWE-medium";
            //yield return "JWE-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult ValidateJwt(string token)
        {
            return ValidateJwtCore(token, policyWithSignatureValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override byte[] WriteJwt(string token)
        {
            return WriteJwtCore(token);
        }
    }
}