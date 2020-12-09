using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateInvalidTokenBenchmark : ValidateInvalidToken
    {
        public override IEnumerable<string> GetTokens()
        {
            yield return "JWS 16 claims";
        }
    }
}
