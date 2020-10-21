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
                                                .RequireSignature(Tokens.SigningKey)
                                                .Build();

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWT")]
        [ArgumentsSource(nameof(GetJwt))]
        public JwtDocument_Reference? TryParseJwt_Reference(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse_Reference(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWS")]
        [ArgumentsSource(nameof(GetJws))]
        public JwtDocument_Reference? TryParseJws_Reference(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse_Reference(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWE")]
        [ArgumentsSource(nameof(GetJwe))]
        public JwtDocument_Reference? TryParseJwe_Reference(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse_Reference(data, policy);
        }

        public JwtDocument_Reference? TryParse_Reference(byte[] data, TokenValidationPolicy policy)
        {
            if (!JwtDocument_Reference.TryParse(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWT")]
        [ArgumentsSource(nameof(GetJwt))]
        public JwtDocument2? TryParseJwt2(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse2(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWS")]
        [ArgumentsSource(nameof(GetJws))]
        public JwtDocument2? TryParseJws2(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse2(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWE")]
        [ArgumentsSource(nameof(GetJwe))]
        public JwtDocument2? TryParseJwe2(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse2(data, policy);
        }

        public JwtDocument2? TryParse2(byte[] data, TokenValidationPolicy policy)
        {
            if (!JwtDocument2.TryParse2(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWT")]
        [ArgumentsSource(nameof(GetJwt))]
        public JwtDocument3? TryParseJwt3(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse3(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWS")]
        [ArgumentsSource(nameof(GetJws))]
        public JwtDocument3? TryParseJws3(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse3(data, policy);
        }

        [Benchmark(Baseline = false)]
        [BenchmarkCategory("JWE")]
        [ArgumentsSource(nameof(GetJwe))]
        public JwtDocument3? TryParseJwe3(byte[] data, TokenValidationPolicy policy)
        {
            return TryParse3(data, policy);
        }

        public JwtDocument3? TryParse3(byte[] data, TokenValidationPolicy policy)
        {
            if (!JwtDocument3.TryParse3(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("JWT")]
        [ArgumentsSource(nameof(GetJwt))]
        public JwtOld? TryReadTokenJwt(byte[] data, TokenValidationPolicy policy)
        {
            return TryReadToken(data, policy);
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("JWS")]
        [ArgumentsSource(nameof(GetJws))]
        public JwtOld? TryReadTokenJws(byte[] data, TokenValidationPolicy policy)
        {
            return TryReadToken(data, policy);
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("JWE")]
        [ArgumentsSource(nameof(GetJwe))]
        public JwtOld? TryReadTokenJwe(byte[] data, TokenValidationPolicy policy)
        {
            return TryReadToken(data, policy);
        }

        public JwtOld? TryReadToken(byte[] data, TokenValidationPolicy policy)
        {
            var reader = new JwtReader(Tokens.EncryptionKey);
            var document = reader.TryReadToken(data, policy);
            if (!document.Succedeed)
            {
                throw new System.Exception();
            }

            return document.Token;
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
