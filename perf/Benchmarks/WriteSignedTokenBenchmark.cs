using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

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
