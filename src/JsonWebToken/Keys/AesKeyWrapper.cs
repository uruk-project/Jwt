using JsonWebToken.ObjectPooling;
using Newtonsoft.Json.Linq;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public class AesKeyWrapper : KeyWrapper
    {
        private const int BlockSizeInBytes = 8;

        private static readonly byte[] _defaultIVArray = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        private static readonly ulong _defaultIV = BitConverter.ToUInt64(_defaultIVArray, 0);
        private static readonly byte[] _emptyIV = BitConverter.GetBytes(0L);

        private readonly ObjectPool<ICryptoTransform> _encryptorPool;
        private readonly ObjectPool<ICryptoTransform> _decryptorPool;

        private readonly Aes _aes;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyWrapper"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public AesKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (key.K == null)
            {
                throw new ArgumentException(ErrorMessages.MalformedKey(key), nameof(key.K));
            }

            _aes = GetSymmetricAlgorithm(key, algorithm);
            _encryptorPool = new ObjectPool<ICryptoTransform>(new PooledEncryptorPolicy(_aes));
            _decryptorPool = new ObjectPool<ICryptoTransform>(new PooledDecryptorPolicy(_aes));
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
                    _encryptorPool.Dispose();
                    _decryptorPool.Dispose();
                    _aes.Dispose();
                    _disposed = true;
                }
            }
        }

        private Aes GetSymmetricAlgorithm(SymmetricJwk key, KeyManagementAlgorithm algorithm)
        {
            byte[] keyBytes = key.RawK;
            ValidateKeySize(keyBytes, algorithm);
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
                throw new InvalidOperationException(ErrorMessages.CreateSymmetricAlgorithmFailed(key, algorithm), ex);
            }
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes.IsEmpty)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                throw new ArgumentException(ErrorMessages.KeySizeMustBeMultipleOf64(keyBytes.Length << 3), nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            return TryUnwrapKeyPrivate(keyBytes, destination, out bytesWritten);
        }

        private unsafe bool TryUnwrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, out int bytesWritten)
        {
            var decryptor = _decryptorPool.Get();
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
                                var b = decryptor.TransformFinalBlock(block, 0, 16);
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
            finally
            {
                _decryptorPool.Return(decryptor);
            }
        }

        private void ValidateKeySize(byte[] key, KeyManagementAlgorithm algorithm)
        {
            if (algorithm.RequiredKeySizeInBits >> 3 != key.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(key.Length), ErrorMessages.KeyWrapKeySizeIncorrect(algorithm, algorithm.RequiredKeySizeInBits >> 3, Key, key.Length << 3));
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

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
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
            var encryptor = _encryptorPool.Get();
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
                            var b = encryptor.TransformFinalBlock(block, 0, 16);
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
            finally
            {
                _encryptorPool.Return(encryptor);
            }
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return GetKeyUnwrappedSize(inputSize, Algorithm);
        }

        public override int GetKeyWrapSize()
        {
            return GetKeyWrappedSize(EncryptionAlgorithm);
        }

        public static int GetKeyUnwrappedSize(int inputSize, KeyManagementAlgorithm algorithm)
        {
            return inputSize - BlockSizeInBytes;
        }

        public static int GetKeyWrappedSize(EncryptionAlgorithm encryptionAlgorithm)
        {
            return encryptionAlgorithm.RequiredKeyWrappedSizeInBytes;
        }

        private class PooledEncryptorPolicy : PooledObjectPolicy<ICryptoTransform>
        {
            private readonly Aes _aes;

            public PooledEncryptorPolicy(Aes aes)
            {
                _aes = aes;
            }

            public override ICryptoTransform Create()
            {
                return _aes.CreateEncryptor();
            }

            public override bool Return(ICryptoTransform obj)
            {
                return true;
            }
        }

        private class PooledDecryptorPolicy : PooledObjectPolicy<ICryptoTransform>
        {
            private readonly Aes _aes;

            public PooledDecryptorPolicy(Aes aes)
            {
                _aes = aes;
            }

            public override ICryptoTransform Create()
            {
                return _aes.CreateDecryptor();
            }

            public override bool Return(ICryptoTransform obj)
            {
                return true;
            }
        }
    }
}
