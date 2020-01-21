using System;
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
            Jwt(new BenchmarkPayload("JWT-0"));
            Wilson(new BenchmarkPayload("JWT-0"));
            WilsonJwt(new BenchmarkPayload("JWT-0"));
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
            return WilsonJwtCore(payload.WilsonJwtDescriptor);
        }

        public override string JoseDotNet(BenchmarkPayload payload)
        {
            throw new NotImplementedException();
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string JwtDotNet(BenchmarkPayload payload)
        {
            return JwtDotNetJwtCore(payload.JoseDescriptor);
        }

        public override IEnumerable<string> GetPayloads()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWT-" + i;
            }
        }
    }
}