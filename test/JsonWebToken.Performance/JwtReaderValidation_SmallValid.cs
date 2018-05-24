//using BenchmarkDotNet.Attributes;
//using BenchmarkDotNet.Diagnosers;
//using BenchmarkDotNet.Running;
//using Jose;
//using JWT;
//using JWT.Algorithms;
//using JWT.Serializers;
//using System.IdentityModel.Tokens.Jwt;

//namespace JsonWebToken.Performance
//{
//    [MemoryDiagnoser]
//    [Config(typeof(DefaultCoreConfig))]
//    public class JwtReaderValidation_SmallValid
//    {
//        private const string Token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";

//        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
//        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
//        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
//        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
//        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
//        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

//        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

//        private static readonly SymmetricJwk SymmetricKey = new SymmetricJwk
//        {
//            Use = "sig",
//            Kid = "kid-hs256",
//            K = "GdaXeVyiJwKmz5LFhcbcng",
//            Alg = "HS256"
//        };

//        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(SymmetricKey);
//        private static readonly TokenValidationParameters validationParameters = new TokenValidationBuilder()
//                                                                                    .RequireSignature(SymmetricKey)
//                                                                                    .AddLifetimeValidation()
//                                                                                    .Build();

//        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SymmetricKey.ToString());

//        [Benchmark(Baseline = true)]
//        public void Wilson()
//        {
//            var result = Handler.ValidateToken(Token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
//            {
//                ValidateAudience = false,
//                ValidateIssuer = false,
//                IssuerSigningKey = WilsonSharedKey
//            }, out var securityToken);
//        }

//        [Benchmark]
//        public void Jwt()
//        {
//            var result = Reader.TryReadToken(Token, validationParameters);
//        }

//        [Benchmark]
//        public void JoseDotNet()
//        {
//            var value = Jose.JWT.Decode(Token, SymmetricKey.RawK, JwsAlgorithm.HS256);
//        }

//        [Benchmark]
//        public void JwtDotNet()
//        {
//            var value = JwtDotNetDecoder.Decode(Token, SymmetricKey.RawK, true);
//        }
//    }
//}
