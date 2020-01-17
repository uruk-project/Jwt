using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteSignedToken : WriteToken
    {
        [Benchmark(Baseline = true, OperationsPerInvoke = 1)]
        [ArgumentsSource(nameof(GetPayloads))]
        public override byte[] Jwt(string payload)
        {
            return JwtCore(payload);
        }

        [Benchmark(OperationsPerInvoke = 1)]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string Wilson(string payload)
        {
            return WilsonCore(payload);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string WilsonJwt(string payload)
        {
            return WilsonJwtCore(payload);
        }

        public IEnumerable<string> GetPayloads()
        {
            yield return "JWS-empty";
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS-" + i;
            }

            //yield return "JWS-empty";
            //yield return "JWS-small";
            //yield return "JWS-medium";
            //yield return "JWS-big";   
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string JoseDotNet(string payload)
        {
            return JoseDotNetJwsCore(payload);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public override string JwtDotNet(string payload)
        {
            return JwtDotNetJwsCore(payload);
        }
    }
}
