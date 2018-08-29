using Newtonsoft.Json.Linq;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public class AesKeyWrapProvider : KeyWrapProvider
    {
        private const int BlockSizeInBytes = 8;

        private static readonly byte[] _defaultIVArray = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        private static readonly ulong _defaultIV = BitConverter.ToUInt64(_defaultIVArray, 0);
        private static readonly byte[] _emptyIV = BitConverter.GetBytes(0L);

        private static readonly object _encryptorLock = new object();
        private static readonly object _decryptorLock = new object();

        private Aes _aes;
        private ICryptoTransform _encryptor;
        private ICryptoTransform _decryptor;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public AesKeyWrapProvider(SymmetricJwk key, in EncryptionAlgorithm encryptionAlgorithm, in KeyManagementAlgorithm algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (!key.IsSupportedAlgorithm(in encryptionAlgorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
            }

            if (!key.IsSupportedAlgorithm(in algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }

            if (key.K == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MalformedKey, key.Kid), nameof(key.K));
            }

            Algorithm = algorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            Key = key;

            _aes = GetSymmetricAlgorithm(key, in algorithm);
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
                    if (_aes != null)
                    {
                        _aes.Dispose();
                        _aes = null;
                    }

                    _disposed = true;
                }
            }
        }

        private Aes GetSymmetricAlgorithm(SymmetricJwk key, in KeyManagementAlgorithm algorithm)
        {
            byte[] keyBytes = key.RawK;
            ValidateKeySize(keyBytes, in algorithm);
            try
            {
                // Create the AES provider
                Aes aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = keyBytes.Length << 3;
                aes.Key = keyBytes;

                // Set the AES IV to Zeroes
                var iv = new byte[aes.BlockSize >> 3];
                Array.Clear(iv, 0, iv.Length);
                aes.IV = iv;

                return aes;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.CreateSymmetricAlgorithmFailed, key.Kid, algorithm), ex);
            }
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes .IsEmpty)
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

            if (_decryptor == null)
            {
                lock (_decryptorLock)
                {
                    if (_decryptor == null)
                    {
                        _decryptor = _aes.CreateDecryptor();
                    }
                }
            }

            return TryUnwrapKeyPrivate(keyBytes, destination, out bytesWritten);
        }

        private unsafe bool TryUnwrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, out int bytesWritten)
        {
            try
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
                fixed (byte* inputPtr = inputBuffer)
                {
                    var a = Unsafe.ReadUnaligned<ulong>(ref *inputPtr);

                    // The number of input blocks
                    var n = (inputBuffer.Length - BlockSizeInBytes) >> 3;

                    // The set of input blocks
                    var r = stackalloc byte[n << 3];
                    for (var i = 0; i < n; i++)
                    {
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref *r, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *inputPtr, (i + 1) << 3)));
                    }

                    byte[] block = new byte[16];

                    fixed (byte* blockPtr = &block[0])
                    {
                        var t = stackalloc byte[8];

                        // Calculate intermediate values
                        for (var j = 5; j >= 0; j--)
                        {
                            for (var i = n; i > 0; i--)
                            {
                                // B = AES-1(K, (A ^ t) | R[i] )                                
                                // T = ( n * j ) + i
                                Unsafe.Add(ref *t, 7) = (byte)((n * j) + i);

                                // First, A = ( A ^ t )
                                a ^= Unsafe.ReadUnaligned<ulong>(ref *t);

                                // Second, block = ( A | R[i] )
                                Unsafe.WriteUnaligned(blockPtr, a);
                                var rValue = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *r, (i - 1) << 3));
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref *blockPtr, 8), rValue);

                                // Third, b = AES-1( block )
                                var b = _decryptor.TransformFinalBlock(block, 0, 16);
                                fixed (byte* bPtr = &b[0])
                                {
                                    // A = MSB(64, B)
                                    a = Unsafe.ReadUnaligned<ulong>(bPtr);

                                    // R[i] = LSB(64, B)
                                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref *r, (i - 1) << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *bPtr, 8)));
                                }
                            }
                        }
                    }

                    if (a == _defaultIV)
                    {
                        fixed (byte* keyBytes = destination)
                        {
                            for (var i = 0; i < n; i++)
                            {
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref *keyBytes, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *r, i << 3)));
                            }
                        }

                        bytesWritten = n << 3;
                        return true;
                    }

                    bytesWritten = 0;
                    return false;
                }
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        private void ValidateKeySize(byte[] key, in KeyManagementAlgorithm algorithm)
        {
            if (algorithm.RequiredKeySizeInBits >> 3 != key.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapKeySizeIncorrect, algorithm, algorithm.RequiredKeySizeInBits >> 3, Key.Kid, key.Length << 3));
            }
        }

        /// <summary>
        /// Wrap a key using RSA encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_encryptor == null)
            {
                lock (_encryptorLock)
                {
                    if (_encryptor == null)
                    {
                        _encryptor = _aes.CreateEncryptor();
                    }
                }
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(in EncryptionAlgorithm, staticKey);
            return TryWrapKeyPrivate(contentEncryptionKey.ToByteArray(), destination, out bytesWritten);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool TryWrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, out int bytesWritten)
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

            try
            {
                // The default initialization vector from RFC3394
                ulong a = _defaultIV;

                // The number of input blocks
                var n = inputBuffer.Length >> 3;

                // The set of input blocks
                var r = stackalloc byte[n << 3];
                fixed (byte* input = inputBuffer)
                {
                    for (var i = 0; i < n; i++)
                    {
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref *r, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *input, i << 3)));
                    }
                }

                byte[] block = new byte[16];
                fixed (byte* blockPtr = &block[0])
                {
                    var t = stackalloc byte[8];
                    Unsafe.As<byte, ulong>(ref *t) = 0;

                    // Calculate intermediate values
                    for (var j = 0; j < 6; j++)
                    {
                        for (var i = 0; i < n; i++)
                        {
                            // B = AES( K, A | R[i] )
                            // First, block = A | R[i]
                            Unsafe.WriteUnaligned(blockPtr, a);
                            Unsafe.WriteUnaligned(ref Unsafe.Add(ref *blockPtr, 8), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *r, i << 3)));

                            // Second, AES( K, block )
                            var b = _encryptor.TransformFinalBlock(block, 0, 16);
                            fixed (byte* bPtr = &b[0])
                            {
                                // A = MSB( 64, B )
                                a = Unsafe.ReadUnaligned<ulong>(bPtr);

                                // T = ( n * j ) + i
                                Unsafe.Add(ref *t, 7) = (byte)((n * j) + i + 1);

                                // A = A ^ t
                                a ^= Unsafe.ReadUnaligned<ulong>(ref t[0]);

                                // R[i] = LSB( 64, B )
                                Unsafe.WriteUnaligned(ref Unsafe.Add(ref *r, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *bPtr, 8)));
                            }
                        }
                    }
                }

                Unsafe.WriteUnaligned(ref destination[0], a);
                for (var i = 0; i < n; i++)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination[0], (i + 1) << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref *r, i << 3)));
                }

                bytesWritten = (n + 1) << 3;
                return true;
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return GetKeyUnwrappedSize(inputSize, in Algorithm);
        }

        public override int GetKeyWrapSize()
        {
            return GetKeyWrappedSize(in EncryptionAlgorithm);
        }

        public static int GetKeyUnwrappedSize(int inputSize, in KeyManagementAlgorithm algorithm)
        {
            return inputSize - BlockSizeInBytes;
        }

        public static int GetKeyWrappedSize(in EncryptionAlgorithm encryptionAlgorithm)
        {
            return encryptionAlgorithm.RequiredKeyWrappedSizeInBytes;
        }
    }
}
