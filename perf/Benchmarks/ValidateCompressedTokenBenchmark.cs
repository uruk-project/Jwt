using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateCompressedTokenBenchmark : ValidateCompressedToken
    {
        public override IEnumerable<string> GetTokens()
        {
            yield return "JWE DEF 06 claims";
        }
    }
}
