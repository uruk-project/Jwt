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
            yield return "JWE-big";
        }

        [Benchmark(OperationsPerInvoke = IterationCount)]
        [ArgumentsSource(nameof(GetTokens))]
        public override void ValidateJwt(string token)
        {
            ValidateJwtCore(token, policyWithSignatureValidation);
        }

        [Benchmark(OperationsPerInvoke = IterationCount)]
        [ArgumentsSource(nameof(GetTokens))]
        public override void WriteJwt(string token)
        {
            WriteJwtCore(token);
        }
    }
}