using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteEncryptedToken : WriteToken
    {

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetPayloads))]
        public override byte[] Jwt(string payload)
        {
            return JwtCore(payload);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string Wilson(string payload)
        {
            return WilsonCore(payload);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string WilsonJwt(string payload)
        {
            return WilsonJwtCore(payload);
        }

        public IEnumerable<string> GetPayloads()
        {
            //yield return "JWE-empty";
            yield return "JWE-small";
            yield return "JWE-medium";
            //yield return "JWE-big";
        }
    }
}