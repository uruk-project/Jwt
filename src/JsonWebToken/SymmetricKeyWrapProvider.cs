using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public class SymmetricKeyWrapProvider : KeyWrapProvider
    {
        private static readonly byte[] _defaultIV = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        private static readonly int _blockSizeInBits = 64;
        private static readonly int _blockSizeInBytes = _blockSizeInBits >> 3;
        private static object _encryptorLock = new object();
        private static object _decryptorLock = new object();

        private SymmetricAlgorithm _symmetricAlgorithm;
        private ICryptoTransform _symmetricAlgorithmEncryptor;
        private ICryptoTransform _symmetricAlgorithmDecryptor;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public SymmetricKeyWrapProvider(SymmetricJwk key, string algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!IsSupportedAlgorithm(key, algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }

            if (key.K == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MalformedKey, key), nameof(key.K));
            }

            Algorithm = algorithm;
            Key = key;

            _symmetricAlgorithm = GetSymmetricAlgorithm(key, algorithm);
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
                    if (_symmetricAlgorithm != null)
                    {
                        _symmetricAlgorithm.Dispose();
                        _symmetricAlgorithm = null;
                    }

                    _disposed = true;
                }
            }
        }

        private static byte[] GetBytes(ulong i)
        {
            byte[] temp = BitConverter.GetBytes(i);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(temp);
            }

            return temp;
        }

        private SymmetricAlgorithm GetSymmetricAlgorithm(SymmetricJwk key, string algorithm)
        {
            byte[] keyBytes = key.RawK;

            ValidateKeySize(keyBytes, algorithm);
            try
            {
                // Create the AES provider
                SymmetricAlgorithm symmetricAlgorithm = Aes.Create();
                symmetricAlgorithm.Mode = CipherMode.ECB;
                symmetricAlgorithm.Padding = PaddingMode.None;
                symmetricAlgorithm.KeySize = keyBytes.Length * 8;
                symmetricAlgorithm.Key = keyBytes;

                // Set the AES IV to Zeroes
                var aesIv = new byte[symmetricAlgorithm.BlockSize >> 3];
                Zero(aesIv);
                symmetricAlgorithm.IV = aesIv;

                return symmetricAlgorithm;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.CreateSymmetricAlgorithmFailed, key, algorithm), ex);
            }
        }

        private bool IsSupportedAlgorithm(SymmetricJwk key, string algorithm)
        {
            if (key == null)
            {
                return false;
            }

            if (string.IsNullOrEmpty(algorithm))
            {
                return false;
            }

            if (algorithm.Equals(SecurityAlgorithms.Aes128KW, StringComparison.Ordinal) || algorithm.Equals(SecurityAlgorithms.Aes256KW, StringComparison.Ordinal))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Unwrap a key using Symmmetric decryption.
        /// </summary>
        /// <param name="keyBytes">bytes to unwrap</param>
        /// <returns>Unwraped key</returns>
        public override byte[] UnwrapKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.KeySizeMustBeMultipleOf64, keyBytes.Length << 3), nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            try
            {
                return UnwrapKeyPrivate(keyBytes, 0, keyBytes.Length);
            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }

        //public override void WrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination)
        //{
        //    if (keyBytes == null || keyBytes.Length == 0)
        //    {
        //        throw new ArgumentNullException(nameof(keyBytes));
        //    }

        //    if (keyBytes.Length % 8 != 0)
        //    {
        //        throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.KeySizeMustBeMultipleOf64, keyBytes.Length << 3), nameof(keyBytes));
        //    }

        //    if (_disposed)
        //    {
        //        throw new ObjectDisposedException(GetType().ToString());
        //    }

        //    try
        //    {
        //        return UnwrapKeyPrivate(keyBytes, 0, keyBytes.Length);
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
        //    }
        //}

        //private byte[] UnwrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, int inputOffset, int inputCount)
        //{
        //    /*
        //        1) Initialize variables.

        //            Set A = C[0]
        //            For i = 1 to n
        //                R[i] = C[i]

        //        2) Compute intermediate values.

        //            For j = 5 to 0
        //                For i = n to 1
        //                    B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
        //                    A = MSB(64, B)
        //                    R[i] = LSB(64, B)

        //        3) Output results.

        //        If A is an appropriate initial value (see 2.2.3),
        //        Then
        //            For i = 1 to n
        //                P[i] = R[i]
        //        Else
        //            Return an error
        //    */
        //    unsafe
        //    {
        //        // A = C[0]
        //        Span<byte> a = stackalloc byte[_blockSizeInBytes];
        //        inputBuffer.Slice(inputOffset, _blockSizeInBytes).CopyTo(a);

        //        // The number of input blocks
        //        var n = (inputCount - _blockSizeInBytes) >> 3;

        //        // The set of input blocks
        //        Span<byte> r = stackalloc byte[n << 3];

        //        inputBuffer.Slice(inputOffset + _blockSizeInBytes, inputCount - _blockSizeInBytes).CopyTo(r);

        //        if (_symmetricAlgorithmDecryptor == null)
        //        {
        //            lock (_decryptorLock)
        //            {
        //                if (_symmetricAlgorithmDecryptor == null)
        //                {
        //                    _symmetricAlgorithmDecryptor = _symmetricAlgorithm.CreateDecryptor();
        //                }
        //            }
        //        }

        //        Span<byte> block = stackalloc byte[16];

        //        // Calculate intermediate values
        //        for (var j = 5; j >= 0; j--)
        //        {
        //            for (var i = n; i > 0; i--)
        //            {
        //                // T = ( n * j ) + i
        //                var t = (ulong)((n * j) + i);

        //                // B = AES-1(K, (A ^ t) | R[i] )

        //                // First, A = ( A ^ t )
        //                Xor(a, GetBytes(t), 0, true);

        //                // Second, block = ( A | R[i] )
        //                a.Slice(0, _blockSizeInBytes).CopyTo(r);
        //                r.Slice((i - 1) << 3, _blockSizeInBytes).CopyTo(block.Slice(_blockSizeInBytes));
        //                //Array.Copy(r, (i - 1) << 3, block, _blockSizeInBytes, _blockSizeInBytes);

        //                // Third, b = AES-1( block )
        //                var b = _symmetricAlgorithmDecryptor.TransformFinalBlock(block, 0, 16);

        //                // A = MSB(64, B)
        //                Array.Copy(b, a, _blockSizeInBytes);

        //                // R[i] = LSB(64, B)
        //                Array.Copy(b, _blockSizeInBytes, r, (i - 1) << 3, _blockSizeInBytes);
        //            }
        //        }

        //        if (AreEqual(a, _defaultIV))
        //        {
        //            var keyBytes = new byte[n << 3];

        //            for (var i = 0; i < n; i++)
        //            {
        //                Array.Copy(r, i << 3, keyBytes, i << 3, 8);
        //            }

        //            return keyBytes;
        //        }
        //        else
        //        {
        //            throw new InvalidOperationException(ErrorMessages.NotAuthenticData);
        //        }
        //    }
        //}


        private byte[] UnwrapKeyPrivate(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            /*
                1) Initialize variables.

                    Set A = C[0]
                    For i = 1 to n
                        R[i] = C[i]

                2) Compute intermediate values.

                    For j = 5 to 0
                        For i = n to 1
                            B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                            A = MSB(64, B)
                            R[i] = LSB(64, B)

                3) Output results.

                If A is an appropriate initial value (see 2.2.3),
                Then
                    For i = 1 to n
                        P[i] = R[i]
                Else
                    Return an error
            */

            // A = C[0]
            byte[] a = new byte[_blockSizeInBytes];

            Array.Copy(inputBuffer, inputOffset, a, 0, _blockSizeInBytes);

            // The number of input blocks
            var n = (inputCount - _blockSizeInBytes) >> 3;

            // The set of input blocks
            byte[] r = new byte[n << 3];

            Array.Copy(inputBuffer, inputOffset + _blockSizeInBytes, r, 0, inputCount - _blockSizeInBytes);

            if (_symmetricAlgorithmDecryptor == null)
            {
                lock (_decryptorLock)
                {
                    if (_symmetricAlgorithmDecryptor == null)
                    {
                        _symmetricAlgorithmDecryptor = _symmetricAlgorithm.CreateDecryptor();
                    }
                }
            }

            byte[] block = new byte[16];

            // Calculate intermediate values
            for (var j = 5; j >= 0; j--)
            {
                for (var i = n; i > 0; i--)
                {
                    // T = ( n * j ) + i
                    var t = (ulong)((n * j) + i);

                    // B = AES-1(K, (A ^ t) | R[i] )

                    // First, A = ( A ^ t )
                    Xor(a, GetBytes(t), 0, true);

                    // Second, block = ( A | R[i] )
                    Array.Copy(a, block, _blockSizeInBytes);
                    Array.Copy(r, (i - 1) << 3, block, _blockSizeInBytes, _blockSizeInBytes);

                    // Third, b = AES-1( block )
                    var b = _symmetricAlgorithmDecryptor.TransformFinalBlock(block, 0, 16);

                    // A = MSB(64, B)
                    Array.Copy(b, a, _blockSizeInBytes);

                    // R[i] = LSB(64, B)
                    Array.Copy(b, _blockSizeInBytes, r, (i - 1) << 3, _blockSizeInBytes);
                }
            }

            if (AreEqual(a, _defaultIV))
            {
                var keyBytes = new byte[n << 3];

                for (var i = 0; i < n; i++)
                {
                    Array.Copy(r, i << 3, keyBytes, i << 3, 8);
                }

                return keyBytes;
            }
            else
            {
                throw new InvalidOperationException(ErrorMessages.NotAuthenticData);
            }
        }

        private void ValidateKeySize(byte[] key, string algorithm)
        {
            if (SecurityAlgorithms.Aes128KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Length != 16)
                {
                    throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeyTooSmall, Key.Kid, algorithm, 128, key.Length << 3));
                }

                return;
            }

            if (SecurityAlgorithms.Aes256KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Length != 32)
                {
                    throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeyTooSmall, Key.Kid, algorithm, 256, key.Length << 3));
                }

                return;
            }

            throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
        }

        /// <summary>
        /// Wrap a key using Symmetric encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>The wrapped key result</returns>
        public override byte[] WrapKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.KeySizeMustBeMultipleOf64, keyBytes.Length << 3), nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            try
            {
                return WrapKeyPrivate(keyBytes, 0, keyBytes.Length);
            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }


#if NETCOREAPP2_1
        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool UnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, out int bytesWriten)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.KeySizeMustBeMultipleOf64, keyBytes.Length << 3), nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            try
            {
                destination = UnwrapKeyPrivate(keyBytes.ToArray(), 0, keyBytes.Length);
                bytesWriten = keyBytes.Length;
                return true;
            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }

        /// <summary>
        /// Wrap a key using RSA encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool WrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, out int bytesWriten)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.KeySizeMustBeMultipleOf64, keyBytes.Length << 3), nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            try
            {
                destination = WrapKeyPrivate(keyBytes.ToArray(), 0, keyBytes.Length);
                bytesWriten = keyBytes.Length;
                return true;

            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }
#endif

        private byte[] WrapKeyPrivate(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            /*
               1) Initialize variables.

                   Set A = IV, an initial value (see 2.2.3)
                   For i = 1 to n
                       R[i] = P[i]

               2) Calculate intermediate values.

                   For j = 0 to 5
                       For i=1 to n
                           B = AES(K, A | R[i])
                           A = MSB(64, B) ^ t where t = (n*j)+i
                           R[i] = LSB(64, B)

               3) Output the results.

                   Set C[0] = A
                   For i = 1 to n
                       C[i] = R[i]
            */

            // The default initialization vector from RFC3394
            byte[] a = _defaultIV.Clone() as byte[];

            // The number of input blocks
            var n = inputCount >> 3;

            // The set of input blocks
            byte[] r = new byte[n << 3];

            Array.Copy(inputBuffer, inputOffset, r, 0, inputCount);

            if (_symmetricAlgorithmEncryptor == null)
            {
                lock (_encryptorLock)
                {
                    if (_symmetricAlgorithmEncryptor == null)
                    {
                        _symmetricAlgorithmEncryptor = _symmetricAlgorithm.CreateEncryptor();
                    }
                }
            }

            byte[] block = new byte[16];

            // Calculate intermediate values
            for (var j = 0; j < 6; j++)
            {
                for (var i = 0; i < n; i++)
                {
                    // T = ( n * j ) + i
                    var t = (ulong)((n * j) + i + 1);

                    // B = AES( K, A | R[i] )

                    // First, block = A | R[i]
                    Array.Copy(a, block, a.Length);
                    Array.Copy(r, i << 3, block, 64 >> 3, 64 >> 3);

                    // Second, AES( K, block )
                    var b = _symmetricAlgorithmEncryptor.TransformFinalBlock(block, 0, 16);

                    // A = MSB( 64, B )
                    Array.Copy(b, a, 64 >> 3);

                    // A = A ^ t
                    Xor(a, GetBytes(t), 0, true);

                    // R[i] = LSB( 64, B )
                    Array.Copy(b, 64 >> 3, r, i << 3, 64 >> 3);
                }
            }

            var keyBytes = new byte[(n + 1) << 3];

            Array.Copy(a, keyBytes, a.Length);

            for (var i = 0; i < n; i++)
            {
                Array.Copy(r, i << 3, keyBytes, (i + 1) << 3, 8);
            }

            return keyBytes;
        }


        private static byte[] Xor(byte[] a, byte[] b, int offset, bool inPlace)
        {
            if (inPlace)
            {
                for (var i = 0; i < a.Length; i++)
                {
                    a[i] = (byte)(a[i] ^ b[offset + i]);
                }

                return a;
            }
            else
            {
                var result = new byte[a.Length];

                for (var i = 0; i < a.Length; i++)
                {
                    result[i] = (byte)(a[i] ^ b[offset + i]);
                }

                return result;
            }
        }

        private static void Zero(byte[] byteArray)
        {
            for (var i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = 0;
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
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        public static bool AreEqual(byte[] a, byte[] b)
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

    }
}
