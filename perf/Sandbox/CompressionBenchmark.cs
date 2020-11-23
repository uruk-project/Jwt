using System;
using System.Buffers;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Compression;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class CompressionBenchmark
    {
        private static readonly DeflateCompressor _compressor = new DeflateCompressor();

        private static byte[] _payload32 = new byte[32];
        private static byte[] _payload256 = new byte[256];
        private static byte[] _payload1024 = new byte[1024];
        private static byte[] _payload4096 = new byte[4096];
        private static byte[] _payload32768 = new byte[32768];

        [Params(32, 256, 1024, 4096, 32768)]
        public int Size { get; set; }

        static CompressionBenchmark()
        {
            RandomNumberGenerator.Fill(_payload32);
            RandomNumberGenerator.Fill(_payload256);
            RandomNumberGenerator.Fill(_payload1024);
            RandomNumberGenerator.Fill(_payload4096);
            RandomNumberGenerator.Fill(_payload32768);
        }

        [Benchmark(Baseline = true)]
        public void Compress_StackallocWhenPossible()
        {
            byte[]? compressedBuffer = null;
            var payload = GetPayload(Size);
            try
            {
                var compressedPayload = payload.Length + 32 > Constants.MaxStackallocBytes
                                                                ? (compressedBuffer = ArrayPool<byte>.Shared.Rent(payload.Length + 32))
                                                                : stackalloc byte[payload.Length + 32];
                int payloadLength = _compressor.Compress(payload, compressedPayload);
                compressedPayload = compressedPayload.Slice(payloadLength);
            }
            finally
            {
                if (compressedBuffer != null)
                {
                    ArrayPool<byte>.Shared.Return(compressedBuffer);
                }
            }
        }

        [Benchmark(Baseline = false)]
        public void Compress_ArrayPoolOnly()
        {
            byte[]? compressedBuffer = null;
            var payload = GetPayload(Size);
            try
            {
                compressedBuffer = ArrayPool<byte>.Shared.Rent(payload.Length + 18);
                int payloadLength = _compressor.Compress(payload, compressedBuffer);
                var compressedPayload = compressedBuffer.AsSpan(payloadLength);
            }
            finally
            {
                if (compressedBuffer != null)
                {
                    ArrayPool<byte>.Shared.Return(compressedBuffer);
                }
            }
        }

        private static byte[] GetPayload(int size)
        {
            switch (size)
            {
                case 32:
                    return _payload32;
                case 256:
                    return _payload256;
                case 1024:
                    return _payload1024;
                case 4096:
                    return _payload4096;
                case 32768:
                    return _payload32768;
                default:
                    break;
            }

            return new byte[0];
        }
    }
}
