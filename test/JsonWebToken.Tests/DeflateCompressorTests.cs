using JsonWebToken.Compression;
using System;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class DeflateCompressorTests
    {
        [Theory]
        [InlineData(1)]
        [InlineData(1024)]
        [InlineData(1024 * 1024 * 1)]
        public void Compress(int size)
        {
            var compressor = new DeflateCompressor();
            var data = new byte[size];
            RandomNumberGenerator.Create().GetBytes(data);
            var compressedData = new byte[16+size * 2];
            int compressedSize = compressor.Compress(data, compressedData);
            using var bw = new PooledByteBufferWriter();
            var decompressor = new DeflateDecompressor();
            decompressor.Decompress(compressedData.AsSpan(0, compressedSize), bw);
            Assert.Equal(data.AsSpan().ToArray(), bw.WrittenSpan.ToArray());
        }
    }
}
