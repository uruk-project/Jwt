using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteSignedTokenBenchmark : WriteSignedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWS 6 claims";
        }
    }
}
