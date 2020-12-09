using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateEncryptedTokenBenchmark : ValidateEncryptedToken
    {
        public override IEnumerable<string> GetTokens()
        {
            yield return "JWE 16 claims";
        }
    }
}
