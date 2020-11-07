using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

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

        [Benchmark(Baseline = false)]
        public void Compress_Stream()
        {
            var payload = GetPayload(Size);
            _compressor.Compress(payload);
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

    [MemoryDiagnoser]
    public class JwtWriterBenchmark
    {
        private static readonly SymmetricJwk _key = SymmetricJwk.GenerateKey(256);

        [Benchmark(Baseline = true)]
        public void Old_Encode()
        {
            var descriptor = new JwsDescriptor
            {
                SigningKey = _key,
                Algorithm = SignatureAlgorithm.HmacSha256,
                IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
                ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
                Issuer = "https://idp.example.com/",
                Audience = "636C69656E745F6964"
            };

            var bufferWriter = new PooledByteBufferWriter();
            var context = new EncodingContext(bufferWriter, null, 0, false);
            descriptor.Encode(context);
            bufferWriter.Dispose();
        }

        [Benchmark(Baseline = false)]
        public void New_Encode()
        {
            var descriptor = new JwsDescriptorX
            {
                SigningKey = _key,
                Alg = SignatureAlgorithm.HmacSha256,
                Payload = new JwtPayloadX
                {
                    { "iat", 1500000000L },
                    { "exp", 2000000000L },
                    { "iss", "https://idp.example.com/" },
                    { "aud", "636C69656E745F6964" }
                }
            };

            var bufferWriter = new PooledByteBufferWriter();
            var context = new EncodingContext(bufferWriter, null, 0, false);
            descriptor.Encode(context);
            bufferWriter.Dispose();
        }
    }

    [MemoryDiagnoser]
    public class JwtWriterBenchmark2
    {
        private static readonly SymmetricJwk _key = SymmetricJwk.GenerateKey(256);
        private static readonly JwsDescriptor _d1 = new JwsDescriptor
        {
            SigningKey = _key,
            Algorithm = SignatureAlgorithm.HmacSha256,
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964"
        };
        private static readonly JwsDescriptorX _d2 = new JwsDescriptorX
        {
            SigningKey = _key,
            Alg = SignatureAlgorithm.HmacSha256,
            Payload = new JwtPayloadX
                {
                    { "iat", 1500000000L },
                    { "exp", 2000000000L },
                    { "iss", "https://idp.example.com/" },
                    { "aud", "636C69656E745F6964" }
                }
        };


        [Benchmark(Baseline = true)]
        public void Old_Encode()
        {
            var bufferWriter = new PooledByteBufferWriter();
            var context = new EncodingContext(bufferWriter, null, 0, false);
            _d1.Encode(context);
            bufferWriter.Dispose();
        }

        [Benchmark(Baseline = false)]
        public void New_Encode()
        {
            var bufferWriter = new PooledByteBufferWriter();
            var context = new EncodingContext(bufferWriter, null, 0, false);
            _d2.Encode(context);
            bufferWriter.Dispose();
        }
    }

    [MemoryDiagnoser]
    public class AesDecryptorBenchmark
    {
        private readonly static AesCbcEncryptor _encryptor;
        private readonly static AesCbcDecryptor _decryptor;
#if SUPPORT_SIMD
        private readonly static Aes128CbcDecryptor _decryptorNi;
#endif
        private readonly static byte[] plaintext;
        private readonly static byte[] nonce;
        private readonly static byte[] key;

        static AesDecryptorBenchmark()
        {
            plaintext = new byte[2048 * 16 + 16];
            key = SymmetricJwk.GenerateKey(128).AsSpan().ToArray();
            nonce = new byte[] { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            _encryptor = new AesCbcEncryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);
            _decryptor = new AesCbcDecryptor(EncryptionAlgorithm.Aes128CbcHmacSha256);
#if SUPPORT_SIMD
            _decryptorNi = new Aes128CbcDecryptor();
#endif
        }



        public static IEnumerable<Item> GetData()
        {
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 1).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray())));
            yield return new Item(GetCiphertext(Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray())));
        }

        public class Item
        {
            public Item(byte[] ciphertext)
            {
                Ciphertext = ciphertext;
            }

            public byte[] Ciphertext { get; }

            public override string ToString()
            {
                return Ciphertext.Length.ToString();
            }
        }

        private static byte[] GetCiphertext(byte[] plaintext)
        {
            var ciphertext = (new byte[(plaintext.Length + 16) & ~15]);

            _encryptor.Encrypt(key, plaintext, nonce, ciphertext);
            return ciphertext;
        }

#if SUPPORT_SIMD
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Decrypt_Simd(Item data)
        {
            return _decryptorNi.TryDecrypt(key, data.Ciphertext, nonce, plaintext, out int bytesWritten);
        }
#endif
    }
}
