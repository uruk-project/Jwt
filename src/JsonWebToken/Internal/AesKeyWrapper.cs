using Newtonsoft.Json.Linq;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
                Errors.ThrowMalformedKey(key);
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
                }

                _disposed = true;
            }
        }

        private static Aes GetSymmetricAlgorithm(SymmetricJwk key, KeyManagementAlgorithm algorithm)
        {
            if (algorithm.RequiredKeySizeInBits != key.KeySizeInBits)
            {
                Errors.ThrowKeyWrapKeySizeIncorrect(algorithm, algorithm.RequiredKeySizeInBits >> 3, key, key.KeySizeInBits);
            }

            byte[] keyBytes = key.RawK;
            Aes aes = null;
            try
            {
                aes = Aes.Create();
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
                if (aes != null)
                {
                    aes.Dispose();
                }

                Errors.ThrowCreateSymmetricAlgorithmFailed(key, algorithm, ex);
                return null;
            }
        }

        /// <summary>
        /// Unwrap a key using AES decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes.IsEmpty)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyBytes.Length % 8 != 0)
            {
                Errors.ThrowKeySizeMustBeMultipleOf64(keyBytes);
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            return TryUnwrapKeyPrivate(keyBytes, destination, out bytesWritten);
        }

        private bool TryUnwrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, out int bytesWritten)
        {
            var decryptor = _decryptorPool.Get();
            try
            {
                ref var inputPtr = ref MemoryMarshal.GetReference(inputBuffer);
                var a = Unsafe.ReadUnaligned<ulong>(ref inputPtr);

                // The number of input blocks
                var n = (inputBuffer.Length - BlockSizeInBytes) >> 3;

                // The set of input blocks
                Span<byte> r = stackalloc byte[n << 3];
                ref var rPtr = ref MemoryMarshal.GetReference<byte>(r);
                for (var i = 0; i < n; i++)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref rPtr, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref inputPtr, (i + 1) << 3)));
                }

                byte[] block = new byte[16];
                ref var blockPtr = ref MemoryMarshal.GetReference<byte>(block);
                Span<byte> t = stackalloc byte[8];
                ref var tPtr = ref MemoryMarshal.GetReference<byte>(t);
                for (var j = 5; j >= 0; j--)
                {
                    for (var i = n; i > 0; i--)
                    {
                        Unsafe.Add(ref tPtr, 7) = (byte)((n * j) + i);
                        a ^= Unsafe.ReadUnaligned<ulong>(ref tPtr);
                        Unsafe.WriteUnaligned(ref blockPtr, a);
                        var rValue = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rPtr, (i - 1) << 3));
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref blockPtr, 8), rValue);
                        var b = decryptor.TransformFinalBlock(block, 0, 16);
                        ref var bPtr = ref MemoryMarshal.GetReference<byte>(b);
                        a = Unsafe.ReadUnaligned<ulong>(ref bPtr);
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref rPtr, (i - 1) << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref bPtr, 8)));
                    }
                }

                if (a == _defaultIV)
                {
                    ref var keyBytes = ref MemoryMarshal.GetReference(destination);
                    for (var i = 0; i < n; i++)
                    {
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref keyBytes, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rPtr, i << 3)));
                    }

                    bytesWritten = n << 3;
                    return true;
                }

                return Errors.TryWriteError(out bytesWritten);
            }
            catch
            {
                return Errors.TryWriteError(out bytesWritten);
            }
            finally
            {
                _decryptorPool.Return(decryptor);
            }
        }

        /// <summary>
        /// Wrap a key using AES encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            return TryWrapKeyPrivate(contentEncryptionKey.ToByteArray(), destination, out bytesWritten);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TryWrapKeyPrivate(ReadOnlySpan<byte> inputBuffer, Span<byte> destination, out int bytesWritten)
        {
            var encryptor = _encryptorPool.Get();
            try
            {
                // The default initialization vector from RFC3394
                ulong a = _defaultIV;
                var n = inputBuffer.Length >> 3;
                Span<byte> r = stackalloc byte[n << 3];
                ref var rPtr = ref MemoryMarshal.GetReference(r);
                ref var input = ref MemoryMarshal.GetReference(inputBuffer);
                for (var i = 0; i < n; i++)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref rPtr, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref input, i << 3)));
                }

                byte[] block = new byte[16];
                ref var blockPtr = ref MemoryMarshal.GetReference<byte>(block);
                Span<byte> t = stackalloc byte[8];
                ref var tPtr = ref MemoryMarshal.GetReference(t);
                Unsafe.As<byte, ulong>(ref tPtr) = 0L;
                for (var j = 0; j < 6; j++)
                {
                    for (var i = 0; i < n; i++)
                    {
                        Unsafe.WriteUnaligned(ref blockPtr, a);
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref blockPtr, 8), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rPtr, i << 3)));

                        var b = encryptor.TransformFinalBlock(block, 0, 16);
                        ref var bPtr = ref MemoryMarshal.GetReference<byte>(b);
                        a = Unsafe.ReadUnaligned<ulong>(ref bPtr);
                        Unsafe.Add(ref tPtr, 7) = (byte)((n * j) + i + 1);
                        a ^= Unsafe.ReadUnaligned<ulong>(ref tPtr);
                        Unsafe.WriteUnaligned(ref Unsafe.Add(ref rPtr, i << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref bPtr, 8)));
                    }
                }

                Unsafe.WriteUnaligned(ref destination[0], a);
                for (var i = 0; i < n; i++)
                {
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination[0], (i + 1) << 3), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rPtr, i << 3)));
                }

                bytesWritten = (n + 1) << 3;
                return true;
            }
            catch
            {
                return Errors.TryWriteError(out bytesWritten);
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
        }
    }
}
