using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteEncryptedTokenBenchmark : WriteEncryptedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWE 06 claims";
        }
    }
}