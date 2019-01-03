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
            //yield return "JWT-big";
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override TokenValidationResult ValidateJwt(string token)
        {
            return ValidateJwtCore(token, TokenValidationPolicy.NoValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokens))]
        public override byte[] WriteJwt(string token)
        {
            return WriteJwtCore(token);
        }
    }
}