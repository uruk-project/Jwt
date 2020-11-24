using System.Collections.Generic;
using System.Linq;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class WriteSignedToken : WriteToken
    {
        [GlobalSetup]
        public void Setup()
        {
            var payload = GetPayloadValues().First();
            JsonWebToken(payload);
            Wilson(payload);
            WilsonJwt(payload);
            jose_jwt(payload);
            Jwt_Net(payload);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override byte[] JsonWebToken(BenchmarkPayload payload)
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
        public override string jose_jwt(BenchmarkPayload payload)
        {
            return JoseDotNetJwsCore(payload.JoseDescriptor);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloadValues))]
        public override string Jwt_Net(BenchmarkPayload payload)
        {
            return JwtDotNetJwsCore(payload.JoseDescriptor);
        }

        public override IEnumerable<string> GetPayloads()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS " + i + "6 claims";
            }
        }
    }
}
