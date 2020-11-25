using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateSignedTokenBenchmark : ValidateSignedToken
    {
        public override IEnumerable<string> GetTokens()
        {
            yield return "JWS 06 claims";
        }
    }
}
