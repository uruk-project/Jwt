using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteCompressedTokenBenchmark : WriteCompressedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWE DEF 6 claims";
        }
    }
}