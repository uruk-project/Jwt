//using BenchmarkDotNet.Attributes;
//using BenchmarkDotNet.Running;
//using JWT;
//using JWT.Algorithms;
//using JWT.Serializers;
//using System;
//using System.Collections.Generic;
//using System.IdentityModel.Tokens.Jwt;

//namespace JsonWebToken.Performance
//{
//    [Config(typeof(DefaultCoreConfig))]
//    public class CacheSignatureProvider
//    {
//        private static readonly SymmetricJwk SymmetricKey = new SymmetricJwk
//        {
//            Use = "sig",
//            Kid = "kid-hs256",
//            K = "GdaXeVyiJwKmz5LFhcbcng",
//            Alg = "HS256"
//        };

//        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader();
//        private static readonly TokenValidationParameters validationParameters = TokenValidationParameters.NoValidation;

//        [Benchmark(Baseline = true)]
//        public void Jwt_NoCache()
//        {
//            JsonWebKey.EnableCache = false;
//            var result = Reader.TryReadToken(Tokens.ValidTokens["small"].AsSpan(), validationParameters);
//            if (!result.Succedeed)
//            {
//                throw new Exception();
//            }
//        }

//        [Benchmark]
//        public void Jwt_Cache()
//        {
//            JsonWebKey.EnableCache = true;
//            var result = Reader.TryReadToken(Tokens.ValidTokens["small"].AsSpan(), validationParameters);
//            if (result == null)
//            {
//                throw new Exception();
//            }
//        }
//    }
//}
