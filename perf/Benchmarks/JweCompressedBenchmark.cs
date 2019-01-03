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
            //yield return "JWE-DEF-big";
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