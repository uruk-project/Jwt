using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public class SymmetricKeyWrapProvider : KeyWrapProvider
    {
        private static readonly byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static readonly byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

        private static readonly byte[] _defaultIV = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        private static readonly int _blockSizeInBits = 64;
        private static readonly int _blockSizeInBytes = _blockSizeInBits >> 3;
        private static readonly object _encryptorLock = new object();
        private static readonly object _decryptorLock = new object();

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

            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!IsSupportedAlgorithm(key, algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }

            if (key.K == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MalformedKey, key.Kid), nameof(key.K));
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
            byte[] bytes = BitConverter.GetBytes(i);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return bytes;
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
                //var aesIv = new byte[symmetricAlgorithm.BlockSize >> 3];
                //Zero(aesIv);
                //symmetricAlgorithm.IV = aesIv;
                Zero(symmetricAlgorithm.IV);

                return symmetricAlgorithm;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.CreateSymmetricAlgorithmFailed, key.Kid, algorithm), ex);
            }
        }

        private bool IsSupportedAlgorithm(SymmetricJwk key, string algorithm)
        {
            if (key == null)
            {
                return false;
            }

            if (algorithm == null)
            {
                return false;
            }

            switch (algorithm)
            {
                case KeyManagementAlgorithms.Aes128KW:
                case KeyManagementAlgorithms.Aes192KW:
                case KeyManagementAlgorithms.Aes256KW:
                    return true;
            }

            return false;
        }

        private byte[] UnwrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, int inputOffset, int inputCount)
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

            var inputArray = inputBuffer.ToArray();
            Array.Copy(inputArray, inputOffset, a, 0, _blockSizeInBytes);

            // The number of input blocks
            var n = (inputCount - _blockSizeInBytes) >> 3;

            // The set of input blocks
            byte[] r = new byte[n << 3];

            Array.Copy(inputArray, inputOffset + _blockSizeInBytes, r, 0, inputCount - _blockSizeInBytes);

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
                    Xor(a, GetBytes(t));

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
            switch (algorithm)
            {
                case KeyManagementAlgorithms.Aes128KW:
                    if (key.Length != 16)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeySizeIncorrect, algorithm, 128, Key.Kid, key.Length << 3));
                    }
                    break;
                case KeyManagementAlgorithms.Aes192KW:
                    if (key.Length != 24)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeySizeIncorrect, algorithm, 192, Key.Kid, key.Length << 3));
                    }
                    break;
                case KeyManagementAlgorithms.Aes256KW:
                    if (key.Length != 32)
                    {
                        throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeySizeIncorrect, algorithm, 256, Key.Kid, key.Length << 3));
                    }
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
            }
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool UnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, out int bytesWritten)
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
                var result = UnwrapKeyPrivate(keyBytes, 0, keyBytes.Length);
                result.CopyTo(destination);
                bytesWritten = result.Length;
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
                var result = WrapKeyPrivate(keyBytes, keyBytes.Length);
                result.CopyTo(destination);
                bytesWriten = result.Length;
                return true;

            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] WrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, int inputCount)
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

            Array.Copy(inputBuffer.ToArray(), 0, r, 0, inputCount);

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
                    Array.Copy(r, i << 3, block, 8, 8);

                    // Second, AES( K, block )
                    var b = _symmetricAlgorithmEncryptor.TransformFinalBlock(block, 0, 16);

                    // A = MSB( 64, B )
                    Array.Copy(b, a, 8);

                    // A = A ^ t
                    Xor(a, GetBytes(t));

                    // R[i] = LSB( 64, B )
                    Array.Copy(b, 8, r, i << 3, 8);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void Xor(byte[] a, byte[] b)
        {
            //for (int i = 0; i < a.Length; i++)
            //{
            //    a[i] = (byte)(a[i] ^ b[i]);
            //}

            fixed (byte* first = &MemoryMarshal.GetReference(a.AsSpan()))
            fixed (byte* second = &MemoryMarshal.GetReference(b.AsSpan()))
            {
                Xor(first, second, a.Length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void Xor(byte* first, byte* second, int length)
        {
            IntPtr i = (IntPtr)0;
            IntPtr n = (IntPtr)(void*)(length * Unsafe.SizeOf<byte>());
            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                n -= Vector<byte>.Count;
                while ((byte*)n >= (byte*)i)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref *first, i), Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref *first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref *second, i)));
                    i += Vector<byte>.Count;
                }

                n += Vector<byte>.Count;
            }

            if ((byte*)n >= (byte*)sizeof(ulong))
            {
                n -= sizeof(ulong);
                while ((byte*)n >= (byte*)i)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref *first, i), Unsafe.As<byte, ulong>(ref Unsafe.AddByteOffset(ref *first, i)) ^ Unsafe.As<byte, ulong>(ref Unsafe.AddByteOffset(ref *second, i)));
                    i += sizeof(ulong);
                }

                n += sizeof(ulong);
            }

            while ((byte*)n > (byte*)i)
            {
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref *first, i), Unsafe.AddByteOffset(ref *first, i) ^ Unsafe.AddByteOffset(ref *second, i));
                i += sizeof(byte);
            }
        }

        private unsafe static void Zero(byte[] byteArray)
        {
                for (var i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = 0;
            }
            //byteArray.AsSpan().Clear();
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
        public static bool AreEqual(byte[] a, byte[] b)
        {
            //int result = 0;
            //byte[] a1, a2;

            //if (a?.Length != b?.Length)
            //{
            //    a1 = s_bytesA;
            //    a2 = s_bytesB;
            //}
            //else
            //{
            //    a1 = a;
            //    a2 = b;
            //}

            //for (int i = 0; i < a1.Length; i++)
            //{
            //    result |= a1[i] ^ a2[i];
            //}

            //return result == 0;
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

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return inputSize - _blockSizeInBytes;
        }

        public override int GetKeyWrapSize(string encryptionAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return 40; // ((256 >> 3 >> 3) + 1) << 3
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return 56; //((384 >> 3 >> 3) + 1) << 3;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return 72; // ((512 >> 3 >> 3) + 1) << 3;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedKeyedHashAlgorithm, encryptionAlgorithm));
        }
    }
}
