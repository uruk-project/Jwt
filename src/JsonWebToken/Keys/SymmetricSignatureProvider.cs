using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.
    /// </summary>
    public class SymmetricSignatureProvider : SignatureProvider
    {
        private bool _disposed;
        private KeyedHashAlgorithm _keyedHash;

        /// <summary>
        /// This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly int DefaultMinimumSymmetricKeySizeInBits = 128;

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

            if (key.KeySize < MinimumKeySizeInBits)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.AlgorithmRequireMinimumKeySize, (algorithm ?? "null"), MinimumKeySizeInBits, key.KeySize));
            }

            _keyedHash = GetKeyedHashAlgorithm(key.RawK, algorithm);
        }

        public override int HashSize => _keyedHash.HashSize;

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
        /// Returns the <see cref="KeyedHashAlgorithm"/>.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        /// <param name="keyBytes">The byte array of the key.</param>
        private KeyedHashAlgorithm GetKeyedHashAlgorithm(byte[] keyBytes, string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256:
                    return new HMACSHA256(keyBytes);

                case SecurityAlgorithms.HmacSha384:
                    return new HMACSHA384(keyBytes);

                case SecurityAlgorithms.HmacSha512:
                    return new HMACSHA512(keyBytes);

                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedKeyedHashAlgorithm, algorithm));
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

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

#if NETCOREAPP2_1
            return _keyedHash.TryComputeHash(input, destination, out bytesWritten);
#else
            try
            {
                var result = _keyedHash.ComputeHash(input.ToArray());
                bytesWritten = input.Length;
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

        public byte[] TrySign(byte[] input)
        {
            return _keyedHash.ComputeHash(input);
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

            if (_disposed)
            {
                throw new ObjectDisposedException(typeof(SymmetricSignatureProvider).ToString());
            }

#if NETCOREAPP2_1
            unsafe
            {
                Span<byte> hash = stackalloc byte[_keyedHash.HashSize / 8];
                return _keyedHash.TryComputeHash(input, hash, out int bytesWritten) && AreEqual(signature, hash);
            }
#else
            return AreEqual(signature, _keyedHash.ComputeHash(input.ToArray()));
#endif
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

            if (_disposed)
            {
                throw new ObjectDisposedException(typeof(SymmetricSignatureProvider).ToString());
            }

#if NETCOREAPP2_1
            unsafe
            {
                Span<byte> hash = stackalloc byte[_keyedHash.HashSize / 8];
                return _keyedHash.TryComputeHash(input, hash, out int bytesWritten) && AreEqual(signature, hash, length);
            }
#else
            return AreEqual(signature, _keyedHash.ComputeHash(input.ToArray()), length);
#endif
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
                    if (_keyedHash != null)
                    {
                        _keyedHash.Dispose();
                        _keyedHash = null;
                    }
                }
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
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(byte[] a, byte[] b, int length)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            int lenToUse = 0;
            byte[] a1, a2;

            if (((a == null) || (b == null))
            || (a.Length < length || b.Length < length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
                lenToUse = a1.Length;
            }
            else
            {
                a1 = a;
                a2 = b;
                lenToUse = length;
            }

            for (int i = 0; i < lenToUse; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(ReadOnlySpan<byte> a, Span<byte> b, int length)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            int lenToUse = 0;
            ReadOnlySpan<byte> a1, a2;

            if (((a == null) || (b == null))
            || (a.Length < length || b.Length < length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
                lenToUse = a1.Length;
            }
            else
            {
                a1 = a;
                a2 = b;
                lenToUse = length;
            }

            for (int i = 0; i < lenToUse; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
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
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(byte[] a, byte[] b)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            byte[] a1, a2;

            if (((a == null) || (b == null))
            || (a.Length != b.Length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
            }
            else
            {
                a1 = a;
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            ReadOnlySpan<byte> a1, a2;

            if (((a == null) || (b == null))
            || (a.Length != b.Length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
            }
            else
            {
                a1 = a;
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }
    }
}
