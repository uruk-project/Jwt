using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteEncryptedToken : WriteToken
    {
        [GlobalSetup]
        public void Setup()
        {
            Jwt(new BenchmarkPayload("JWE-0"));
            Wilson(new BenchmarkPayload("JWE-0"));
            WilsonJwt(new BenchmarkPayload("JWE-0"));
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
            return WilsonJweCore(payload.WilsonJwtDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string JoseDotNet(BenchmarkPayload payload)
        {
            return JoseDotNetJweCore(payload.JoseDescriptor);
        }

        public override string JwtDotNet(BenchmarkPayload payload)
        {
            throw new System.NotImplementedException();
        }

        public override IEnumerable<string> GetPayloads()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWE-" + i;
            }
        }
    }
}