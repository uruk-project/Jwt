using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JwtWriter_EmptyToken
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var descriptor = new SecurityTokenDescriptor();
            var value = Handler.CreateEncodedJwt(descriptor);
        }


        [Benchmark]
        public void JoseDotNet()
        {
            var payload = new Dictionary<string, object>();
            var value = Jose.JWT.Encode(payload, string.Empty, JwsAlgorithm.none);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var payload = new Dictionary<string, object>();
            var value = JwtDotNetEncoder.Encode(payload, string.Empty);
        }

        [Benchmark]
        public void Custom()
        {
            var descriptor = new JsonWebTokenDescriptor();
            var value = Writer.WriteToken(descriptor);
        }
    }
}
