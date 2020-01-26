using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteEncryptedTokenBenchmark : WriteEncryptedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWE 6 claims";
        }
    }
}