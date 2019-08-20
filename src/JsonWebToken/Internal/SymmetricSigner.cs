// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.
    /// </summary>
    internal sealed class SymmetricSigner : Signer
    {
        private readonly ObjectPool<KeyedHashAlgorithm> _hashAlgorithmPool;
        private bool _disposed;

        /// <summary>
        /// This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly int DefaultMinimumSymmetricKeySizeInBits = 128;

        private readonly int _hashSizeInBytes;
        private readonly int _base64HashSizeInBytes;
        private int _minimumKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        public SymmetricSigner(SymmetricJwk key, SignatureAlgorithm algorithm)
            : base(key, algorithm)
        {
            if (key.KeySizeInBits < MinimumKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(key, algorithm.Name, MinimumKeySizeInBits, key.KeySizeInBits);
            }

            if (algorithm.Category != AlgorithmCategory.Hmac)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(algorithm);
            }

            _hashSizeInBytes = Algorithm.RequiredKeySizeInBits >> 2;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _hashAlgorithmPool = Algorithm.Id switch
            {
                Algorithms.HmacSha256 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha256ObjectPoolPolicy(key.ToArray())),
                Algorithms.HmacSha384 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha384ObjectPoolPolicy(key.ToArray())),
                Algorithms.HmacSha512 => new ObjectPool<KeyedHashAlgorithm>(new HmacSha512ObjectPoolPolicy(key.ToArray())),
                _ => new ObjectPool<KeyedHashAlgorithm>(new NotSupportedObjectPoolPolicy(algorithm)),
            };
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricJwk"/>.KeySize.
        /// </summary>
        public int MinimumKeySizeInBits
        {
            get
            {
                return _minimumKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.value, DefaultMinimumSymmetricKeySizeInBits);
                }

                _minimumKeySizeInBits = value;
            }
        }

        /// <inheritsdoc />
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if !NETSTANDARD2_0
                return keyedHash.TryComputeHash(input, destination, out bytesWritten);
#else
                try
                {
                    var result = keyedHash.ComputeHash(input.ToArray());
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                    return true;
                }
                catch
                {
                    return ThrowHelper.TryWriteError(out bytesWritten);
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        /// <inheritsdoc />
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if !NETSTANDARD2_0
                Span<byte> hash = stackalloc byte[_hashSizeInBytes];
                bool result = keyedHash.TryComputeHash(input, hash, out int bytesWritten) && AreEqual(signature, hash);
                Debug.Assert(hash.Length == bytesWritten);
                return result;
#else
                return AreEqual(signature, keyedHash.ComputeHash(input.ToArray()));
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        // Optimized byte-based AreEqual. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private unsafe static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            int length = a.Length;
            fixed (byte* pA = a)
            fixed (byte* pB = b)
            {
                byte* first = pA;
                byte* second = pB;
                if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count)
                {
                    Vector<byte> equals = new Vector<byte>();

                    var firstEnd = first + length - Vector<byte>.Count;
                    var secondEnd = second + length - Vector<byte>.Count;
                    while (first < firstEnd)
                    {
                        equals |= Unsafe.ReadUnaligned<Vector<byte>>(first)
                            - Unsafe.ReadUnaligned<Vector<byte>>(second);
                        first += Vector<byte>.Count;
                        second += Vector<byte>.Count;
                    }

                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(firstEnd)
                        - Unsafe.ReadUnaligned<Vector<byte>>(secondEnd);
                    return equals == Vector<byte>.Zero;
                }
                else if (length >= sizeof(long))
                {
                    long equals = 0L;

                    var firstEnd = first + length - sizeof(long);
                    var secondEnd = second + length - sizeof(long);
                    while (first < firstEnd)
                    {
                        equals |= *(long*)first - *(long*)second;
                        first += sizeof(long);
                        second += sizeof(long);
                    }

                    equals |= *(long*)firstEnd - *(long*)(secondEnd);
                    return equals == 0L;
                }
                else
                {
                    int equals = 0;

                    var firstEnd = first + length - sizeof(long);
                    while (first < firstEnd)
                    {
                        equals |= *first - *first;
                        first += 1;
                        second += 1;
                    }

                    return equals == 0;
                }
            }
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithmPool.Dispose();
                }

                _disposed = true;
            }
        }

        private sealed class HmacSha256ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha256ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA256(_keyBytes);
            }
        }

        private sealed class HmacSha384ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha384ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA384(_keyBytes);
            }
        }

        private sealed class HmacSha512ObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            private readonly byte[] _keyBytes;

            public HmacSha512ObjectPoolPolicy(byte[] keyBytes)
            {
                _keyBytes = keyBytes;
            }

            public override KeyedHashAlgorithm Create()
            {
                return new HMACSHA512(_keyBytes);
            }
        }

        private sealed class NotSupportedObjectPoolPolicy : PooledObjectFactory<KeyedHashAlgorithm>
        {
            public NotSupportedObjectPoolPolicy(SignatureAlgorithm algorithm)
            {
                ThrowHelper.ThrowNotSupportedException_KeyedHashAlgorithm(algorithm);
            }

            public override KeyedHashAlgorithm Create()
            {
                throw new NotSupportedException();
            }
        }
    }
}
