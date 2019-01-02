using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    public class JwtBenchmark : JwtBenchmarkBase
    {
        public IEnumerable<string> GetTokens()
        {
            yield return "JWT-empty";
            yield return "JWT-small";
            yield return "JWT-medium";
            yield return "JWT-big";
        }

        [Benchmark(OperationsPerInvoke = IterationCount)]
        [ArgumentsSource(nameof(GetTokens))]
        public override void ValidateJwt(string token)
        {
            ValidateJwtCore(token, TokenValidationPolicy.NoValidation);
        }

        [Benchmark(OperationsPerInvoke = IterationCount)]
        [ArgumentsSource(nameof(GetTokens))]
        public override void WriteJwt(string token)
        {
            WriteJwtCore(token);
        }
    }
}