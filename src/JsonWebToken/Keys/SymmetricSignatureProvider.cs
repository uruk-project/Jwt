using JsonWebToken.ObjectPooling;
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
    public class SymmetricSignatureProvider : SignatureProvider
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
        /// Initializes a new instance of the <see cref="SymmetricSignatureProvider"/> class that uses an <see cref="JsonWebKey"/> to create and / or verify signatures over a array of bytes.
        /// </summary>
        /// <param name="key">The <see cref="SymmetricJwk"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to use.</param>
        public SymmetricSignatureProvider(SymmetricJwk key, string algorithm)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.KeySizeInBits < MinimumKeySizeInBits)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.AlgorithmRequireMinimumKeySize, (algorithm ?? "null"), MinimumKeySizeInBits, key.KeySizeInBits));
            }

            switch (Algorithm)
            {
                case SignatureAlgorithms.HmacSha256:
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha256ObjectPoolPolicy(key.RawK));
                    _hashSizeInBytes = 32;
                    break;
                case SignatureAlgorithms.HmacSha384:
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha384ObjectPoolPolicy(key.RawK));
                    _hashSizeInBytes = 48;
                    break;
                case SignatureAlgorithms.HmacSha512:
                    _hashAlgorithmPool = new ObjectPool<KeyedHashAlgorithm>(new HmacSha512ObjectPoolPolicy(key.RawK));
                    _hashSizeInBytes = 64;
                    break;
                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedKeyedHashAlgorithm, algorithm));
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
                    throw new ArgumentOutOfRangeException(nameof(value), ErrorMessages.FormatInvariant(ErrorMessages.MustBeAtLeast, nameof(DefaultMinimumSymmetricKeySizeInBits), DefaultMinimumSymmetricKeySizeInBits));
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
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
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
                    bytesWritten = 0;
                    return false;
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
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature == null || signature.Length == 0)
            {
                throw new ArgumentNullException(nameof(signature));
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
            if (input == null || input.Length == 0)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature == null || signature.Length == 0)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (length <= 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(length), length));
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
        /// <param name="length">length of array to check</param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        private static bool AreEqual(ReadOnlySpan<byte> a, Span<byte> b, int length)
        {
            int lenToUse = 0;
            ReadOnlySpan<byte> first, second;

            if (((a == null) || (b == null)) || (a.Length < length || b.Length < length))
            {
                first = s_bytesA;
                second = s_bytesB;
                lenToUse = first.Length;
            }
            else
            {
                first = a;
                second = b;
                lenToUse = length;
            }

            return AreEqual(ref MemoryMarshal.GetReference(first), ref MemoryMarshal.GetReference(second), lenToUse);
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
        unsafe private static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            ReadOnlySpan<byte> first, second;

            if (((a == null) || (b == null)) || (a.Length != b.Length))
            {
                first = s_bytesA;
                second = s_bytesB;
            }
            else
            {
                first = a;
                second = b;
            }

            return AreEqual(ref MemoryMarshal.GetReference(first), ref MemoryMarshal.GetReference(second), first.Length);
        }

        // Optimized byte-based AreEqual. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                bool equals = true;
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) ^ Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                }
            }
        }

        private class HmacSha256ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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

            public override bool Return(KeyedHashAlgorithm obj)
            {
                return true;
            }
        }

        private class HmacSha384ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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

            public override bool Return(KeyedHashAlgorithm obj)
            {
                return true;
            }
        }

        private class HmacSha512ObjectPoolPolicy : PooledObjectPolicy<KeyedHashAlgorithm>
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

            public override bool Return(KeyedHashAlgorithm obj)
            {
                return true;
            }
        }
    }
}
