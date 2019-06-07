using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class ByteArrayCopy
    {
        private readonly byte[] small = new byte[32];
        private readonly byte[] medium = new byte[1024];
        private readonly byte[] big = new byte[1048576];

        private byte[] destination = new byte[1048576];

        public ByteArrayCopy()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetNonZeroBytes(small);
                rnd.GetNonZeroBytes(medium);
                rnd.GetNonZeroBytes(big);
            }
        }

        [Benchmark(Baseline = true)]
        public void ArrayCopy_Small()
        {
            Array.Copy(small, destination, small.Length);
        }

        [Benchmark]
        public void ArrayCopy_Medium()
        {
            Array.Copy(medium, destination, medium.Length);
        }

        [Benchmark]
        public void ArrayCopy_Big()
        {
            Array.Copy(big, destination, big.Length);
        }

        [Benchmark]
        public void SpanCopyToArray_Small()
        {
            small.AsSpan().CopyTo(destination);
        }

        [Benchmark]
        public void SpanCopyToArray_Medium()
        {
            medium.AsSpan().CopyTo(destination);
        }

        [Benchmark]
        public void SpanCopyToArray_Big()
        {
            big.AsSpan().CopyTo(destination);
        }
        [Benchmark]
        public void SpanCopyToSpan_Small()
        {
            small.AsSpan().CopyTo(destination.AsSpan());
        }

        [Benchmark]
        public void SpanCopyToSpan_Medium()
        {
            medium.AsSpan().CopyTo(destination.AsSpan());
        }

        [Benchmark]
        public void SpanCopyToSpan_Big()
        {
            big.AsSpan().CopyTo(destination.AsSpan());
        }
        [Benchmark]
        public void ArrayCopyToSpan_Small()
        {
            small.CopyTo(destination.AsSpan());
        }

        [Benchmark]
        public void ArrayCopyToSpan_Medium()
        {
            medium.CopyTo(destination.AsSpan());
        }

        [Benchmark]
        public void ArrayCopyToSpan_Big()
        {
            big.CopyTo(destination.AsSpan());
        }

        [Benchmark]
        public void ArrayCopyToArray_Small()
        {
            small.CopyTo(destination, 0);
        }

        [Benchmark]
        public void ArrayCopyToArray_Medium()
        {
            medium.CopyTo(destination, 0);
        }

        [Benchmark]
        public void ArrayCopyToArray_Big()
        {
            big.CopyTo(destination, 0);
        }
    }
}
