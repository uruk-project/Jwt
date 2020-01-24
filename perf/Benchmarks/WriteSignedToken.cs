using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteSignedToken : WriteToken
    {
        [GlobalSetup]
        public void Setup()
        {
            Jwt(new BenchmarkPayload("JWS-0"));
            Wilson(new BenchmarkPayload("JWS-0"));
            WilsonJwt(new BenchmarkPayload("JWS-0"));
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override byte[] Jwt(BenchmarkPayload payload)
        {
            return JwtCore(payload.JwtDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string Wilson(BenchmarkPayload payload)
        {
            return WilsonCore(payload.WilsonDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string WilsonJwt(BenchmarkPayload payload)
        {
            return WilsonJwsCore(payload.WilsonJwtDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string JoseDotNet(BenchmarkPayload payload)
        {
            return JoseDotNetJwsCore(payload.JoseDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string JwtDotNet(BenchmarkPayload payload)
        {
            return JwtDotNetJwsCore(payload.JoseDescriptor);
        }

        public override IEnumerable<string> GetPayloads()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS-" + i;
            }
        }
    }
}
