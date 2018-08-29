using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class ValueTypeParameters
    {
        [Benchmark(Baseline = true)]
        public void Standard()
        {
            var value = EncryptionAlgorithm.Aes128CbcHmacSha256;
            MethodStandard(value);
        }

        [Benchmark]
        public void In()
        {
            var value = EncryptionAlgorithm.Aes128CbcHmacSha256;
            MethodIn(value);
        }

        [Benchmark]
        public void In2()
        {
            var value = EncryptionAlgorithm.Aes128CbcHmacSha256;
            MethodIn(in value);
        }

        [Benchmark]
        public void Ref()
        {
            var value = EncryptionAlgorithm.Aes128CbcHmacSha256;
            MethodRef(ref value);
        }

        private void MethodStandard(EncryptionAlgorithm value)
        {
            var v = value;
        }

        private void MethodIn(in EncryptionAlgorithm value)
        {
            var v = value;
        }

        private void MethodRef(ref EncryptionAlgorithm value)
        {
            var v = value;
        }
    }
}
