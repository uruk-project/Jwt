using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    public class JweCompressedBenchmark : JwtBenchmarkBase
    {
        public IEnumerable<string> GetTokens()
        {
            yield return "JWE-DEF-empty";
            yield return "JWE-DEF-small";
            yield return "JWE-DEF-medium";
            yield return "JWE-DEF-big";
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