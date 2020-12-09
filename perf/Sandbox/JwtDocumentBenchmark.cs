using System;
using System.Collections.Generic;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    [CategoriesColumn]
    public class JwtDocumentBenchmark
    {
        private static readonly TokenValidationPolicy _policy = new TokenValidationPolicyBuilder()
                                                .WithDecryptionKeys(Tokens.EncryptionKey)
                                                .RequireSignatureByDefault(Tokens.SigningKey)
                                                .Build();

        //[Benchmark(Baseline = false)]
        //[BenchmarkCategory("JWT")]
        //[ArgumentsSource(nameof(GetJwt))]
        //public JwtDocument2? TryParseJwt2(byte[] data, TokenValidationPolicy policy)
        //{
        //    return TryParse2(data, policy);
        //}

        //[Benchmark(Baseline = false)]
        //[BenchmarkCategory("JWS")]
        //[ArgumentsSource(nameof(GetJws))]
        //public JwtDocument2? TryParseJws2(byte[] data, TokenValidationPolicy policy)
        //{
        //    return TryParse2(data, policy);
        //}

        //[Benchmark(Baseline = false)]
        //[BenchmarkCategory("JWE")]
        //[ArgumentsSource(nameof(GetJwe))]
        //public JwtDocument2? TryParseJwe2(byte[] data, TokenValidationPolicy policy)
        //{
        //    return TryParse2(data, policy);
        //}

        //private JwtDocument2? TryParse2(byte[] data, TokenValidationPolicy policy)
        //{
        //    if (!JwtDocument2.TryParse2(data, policy, out var document))
        //    {
        //        throw new System.Exception();
        //    }

        //    document.Dispose();
        //    return document;
        //}

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWT")]
        [ArgumentsSource(nameof(GetJwt))]
        public Jwt? TryParseJwt(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWS")]
        [ArgumentsSource(nameof(GetJws))]
        public Jwt? TryParseJws(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWE")]
        [ArgumentsSource(nameof(GetJwe))]
        public Jwt? TryParseJwe(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse(data, policy);
        }

        private Jwt? TryParse(byte[] data, TokenValidationPolicy policy)
        {
            if (!Jwt.TryParse(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        public static IEnumerable<object[]> GetJwe()
        {
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 6 claims"]), _policy };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 96 claims"]), _policy };
        }
        public static IEnumerable<object[]> GetJws()
        {
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 6 claims"]), _policy };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 96 claims"]), _policy };
        }
        public static IEnumerable<object[]> GetJwt()
        {
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWT 6 claims"]), TokenValidationPolicy.NoValidation };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWT 96 claims"]), TokenValidationPolicy.NoValidation };
        }
    }
}
