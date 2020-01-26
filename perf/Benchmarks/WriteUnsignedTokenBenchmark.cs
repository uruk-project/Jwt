using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteUnsignedTokenBenchmark : WriteUnsignedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWT 6 claims";
        }
    }
}