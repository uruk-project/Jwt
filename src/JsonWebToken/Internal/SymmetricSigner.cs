using System;
using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.
    /// </summary>
    public sealed class SymmetricSigner : Signer
    {
        private static readonly byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static readonly byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

        private readonly ObjectPool<KeyedHashAlgorithm> _hashAlgorithmPool;
        private bool _disposed;

        /// <summary>
        /// This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly int DefaultMinimumSymmetricKeySizeInBits = 128;
        private readonly int _hashSizeInBytes;
        private int _minimumKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricSigner"/> class that uses an <see cref="JsonWebKey"/> to create and / or verify signatures over a array of bytes.
        /// </summary>
        /// <param name="key">The <see cref="SymmetricJwk"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to use.</param>
        public SymmetricSigner(SymmetricJwk key, SignatureAlgorithm algorithm)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (key.KeySizeInBits < MinimumKeySizeInBits)
            {
                Errors.ThrowAlgorithmRequireMinimumKeySize(key, algorithm.Name, MinimumKeySizeInBits, key.KeySizeInBits);
            }

            if (algorithm.Category != AlgorithmCategory.Symmetric)
            {
                Errors.ThrowNotSupportedSignatureAlgorithm(algorithm);
            }

            _hashSizeInBytes = Algorithm.RequiredKeySizeInBits >> 2;
            switch (Algorithm.Name)
            {
                case "HS256":
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha256ObjectPoolPolicy(key.RawK));
                    break;
                case "HS384":
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha384ObjectPoolPolicy(key.RawK));
                    break;
                case "HS512":
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha512ObjectPoolPolicy(key.RawK));
                    break;
                default:
                    Errors.ThrowNotSupportedKeyedHashAlgorithm(algorithm);
                    break;
            }
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricJwk"/>.KeySize"/>.
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
                    Errors.ThrowMustBeAtLeast(nameof(DefaultMinimumSymmetricKeySizeInBits), DefaultMinimumSymmetricKeySizeInBits);
                }

                _minimumKeySizeInBits = value;
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SymmetricJwk"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( JsonWebKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to sign.</param>
        /// <returns>Signed bytes</returns>
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
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
                    return Errors.TryWriteError(out bytesWritten);
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature. Using <see cref="SymmetricJwk"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( JsonWebKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if computed signature matches the signature parameter, false otherwise.</returns>
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
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

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature. Using <see cref="SymmetricJwk"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( JsonWebKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <param name="length">number of bytes of signature to use.</param>
        /// <returns>true if computed signature matches the signature parameter, false otherwise.</returns>
        public bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature, int length)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (length <= 0)
            {
                Errors.ThrowMustBeGreaterThanZero(nameof(length), length);
            }

            var keyedHash = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                Span<byte> hash = stackalloc byte[_hashSizeInBytes];
                bool result = keyedHash.TryComputeHash(input, hash, out int bytesWritten) && AreEqual(signature, hash, length);
                Debug.Assert(hash.Length == bytesWritten);
                return result;
#else
                return AreEqual(signature, keyedHash.ComputeHash(input.ToArray()), length);
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(keyedHash);
            }
        }

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        private static bool AreEqual(ReadOnlySpan<byte> a, Span<byte> b)
        {
            return AreEqual(a, b, a.Length);
        }

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        // Optimized byte-based AreEqual. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int length)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            ref var first = ref MemoryMarshal.GetReference(a);
            ref byte second = ref MemoryMarshal.GetReference(b);

            if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count)
            {
                Vector<byte> equals = default;
                ref var firstEnd = ref Unsafe.Add(ref first, length - Vector<byte>.Count);
                ref var secondEnd = ref Unsafe.Add(ref second, length - Vector<byte>.Count);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref first) - Unsafe.ReadUnaligned<Vector<byte>>(ref second);
                    first = ref Unsafe.Add(ref first, Vector<byte>.Count);
                    second = ref Unsafe.Add(ref second, Vector<byte>.Count);
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref firstEnd) - Unsafe.ReadUnaligned<Vector<byte>>(ref secondEnd);
                return equals == Vector<byte>.Zero;
            }

            if (length >= sizeof(long))
            {
                long equals = 0L;
                ref var firstEnd = ref Unsafe.Add(ref first, length - sizeof(long));
                ref var secondEnd = ref Unsafe.Add(ref second, length - sizeof(long));
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<long>(ref first) - Unsafe.ReadUnaligned<long>(ref second);
                    first = ref Unsafe.Add(ref first, sizeof(long));
                    second = ref Unsafe.Add(ref second, sizeof(long));
                }

                equals |= Unsafe.ReadUnaligned<long>(ref firstEnd) - Unsafe.ReadUnaligned<long>(ref secondEnd);
                return equals == 0L;
            }
            else
            {
                int equals = 0;
                ref var firstEnd = ref Unsafe.Add(ref first, length);
                ref var secondEnd = ref Unsafe.Add(ref second, length);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<byte>(ref first) - Unsafe.ReadUnaligned<byte>(ref second);
                    first = ref Unsafe.Add(ref first, 1);
                    second = ref Unsafe.Add(ref second, 1);
                }

                return equals == 0;
            }
        }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
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

        private sealed class HmacSha256ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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

        private sealed class HmacSha384ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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

        private sealed class HmacSha512ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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
    }
}
