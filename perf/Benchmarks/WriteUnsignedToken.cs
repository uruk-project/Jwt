using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteUnsignedToken : WriteToken
    {
        [GlobalSetup]
        public void Setup()
        {
            Jwt("JWT-empty");
            Wilson("JWT-empty");
            WilsonJwt("JWT-empty");
        }

        [Benchmark(Baseline = true, OperationsPerInvoke = 16)]
        [ArgumentsSource(nameof(GetPayloads))]
        public override byte[] Jwt(string payload)
        {
            return JwtCore(payload);
        }

        [Benchmark(OperationsPerInvoke = 16)]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string Wilson(string payload)
        {
            return WilsonCore(payload);
        }

        //[Benchmark]
        //[ArgumentsSource(nameof(GetPayloads))]
        public override string WilsonJwt(string payload)
        {
            return WilsonJwtCore(payload);
        }

        public IEnumerable<string> GetPayloads()
        {
            yield return "JWT-empty";
            yield return "JWT-small";
            //yield return "JWT-medium";
            //yield return "JWT-big";
        }
    }
}