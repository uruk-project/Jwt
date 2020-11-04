using System;
using System.Collections.Generic;
using System.Linq;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class WriteUnsignedToken : WriteToken
    {
        [GlobalSetup]
        public void Setup()
        {
            var payload = GetPayloadValues().First();
            JsonWebToken(payload);
            Wilson(payload);
            WilsonJwt(payload);
            Jwt_Net(payload);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override byte[] JsonWebToken(BenchmarkPayload payload)
        {
            return JwtCore(payload.JwtDescriptor);
        }
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override byte[] JsonWebTokenX(BenchmarkPayload payload)
        {
            return JwtCoreX(payload.JwtDescriptorX);
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

        public override string jose_jwt(BenchmarkPayload payload)
        {
            throw new NotImplementedException();
        }

        public override string Jwt_Net(BenchmarkPayload payload)
        {
            return string.Empty;
        }

        public override IEnumerable<string> GetPayloads()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWT " + (i == 0 ? "" : i.ToString()) + "6 claims";
            }
        }
    }
}