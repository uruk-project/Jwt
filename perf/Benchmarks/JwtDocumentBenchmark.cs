using System.Collections.Generic;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JwtDocumentBenchmark
    {
        private static readonly TokenValidationPolicy _policy = new TokenValidationPolicyBuilder()
                                                .WithDecryptionKeys(Tokens.EncryptionKey)
                                                .RequireSignature(Tokens.SigningKey)
                                                .Build();

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public JwtDocument? TryParse(byte[] data, TokenValidationPolicy policy)
        {
            if (!JwtDocument.TryParse(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public JwtDocument2? TryParse2(byte[] data, TokenValidationPolicy policy)
        {
            if (!JwtDocument2.TryParse(data, policy, out var document))
            {
                throw new System.Exception();
            }

            document.Dispose();
            return document;
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public Jwt? TryReadToken(byte[] data, TokenValidationPolicy policy)
        {
            var reader = new JwtReader(Tokens.EncryptionKey);
            var document = reader.TryReadToken(data, policy);
            if (!document.Succedeed)
            {
                throw new System.Exception();
            }

            return document.Token;
        }

        public static IEnumerable<object[]> GetData()
        {
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWT 6 claims"]), TokenValidationPolicy.NoValidation };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWT 96 claims"]), TokenValidationPolicy.NoValidation };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 6 claims"]), _policy };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWS 96 claims"]), _policy };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 6 claims"]), _policy };
            yield return new object[] { Encoding.UTF8.GetBytes(Tokens.ValidTokens["JWE 96 claims"]), _policy };
        }
    }
}
