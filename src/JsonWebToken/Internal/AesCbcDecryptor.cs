// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    public sealed class AesCbcDecryptor : AesDecryptor
    {
        private readonly ObjectPool<Aes> _aesPool;
        private bool _disposed;

        public AesCbcDecryptor(ReadOnlySpan<byte> key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;
            if (key.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, encryptionAlgorithm.RequiredKeySizeInBits >> 4);
            }

            var aesKey = key.ToArray();

            _aesPool = new ObjectPool<Aes>(new AesPooledPolicy(aesKey));
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (nonce.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            Aes aes = _aesPool.Get();
            try
            {
                aes.IV = nonce.ToArray();
                using (var decryptor = aes.CreateDecryptor())
                {
                    bytesWritten = Transform(decryptor, ciphertext, 0, ciphertext.Length, plaintext);
                }

                return bytesWritten <= ciphertext.Length;
            }
            finally
            {
                _aesPool.Return(aes);
            }
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _aesPool.Dispose();
                _disposed = true;
            }
        }

        private static int Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength, Span<byte> output)
        {
            byte[] buffer = input.ToArray();
            int offset = inputOffset;
            int count = inputLength;
            var _inputBlockSize = transform.InputBlockSize;
            var _outputBlockSize = transform.OutputBlockSize;

            var _inputBuffer = new byte[_inputBlockSize];
            var _outputBuffer = new byte[_outputBlockSize];
            int _inputBufferIndex = 0;

            // write <= count bytes to the output stream, transforming as we go.
            // Basic idea: using bytes in the _InputBuffer first, make whole blocks,
            // transform them, and write them out.  Cache any remaining bytes in the _InputBuffer.
            int bytesToWrite = count;
            int currentInputIndex = offset;

            // if we have some bytes in the _InputBuffer, we have to deal with those first,
            // so let's try to make an entire block out of it
            int numOutputBytes;
            int outputLength = 0;
            while (bytesToWrite > 0)
            {
                if (bytesToWrite >= _inputBlockSize)
                {
                    // We have at least an entire block's worth to transform
                    int numWholeBlocks = bytesToWrite / _inputBlockSize;

                    // If the transform will handle multiple blocks at once, do that
                    if (transform.CanTransformMultipleBlocks && numWholeBlocks > 1)
                    {
                        int numWholeBlocksInBytes = numWholeBlocks * _inputBlockSize;

                        // Use ArrayPool.Shared instead of CryptoPool because the array is passed out.
                        byte[] tempOutputBuffer = ArrayPool<byte>.Shared.Rent(numWholeBlocks * _outputBlockSize);
                        numOutputBytes = 0;

                        try
                        {
                            numOutputBytes = transform.TransformBlock(buffer, currentInputIndex, numWholeBlocksInBytes, tempOutputBuffer, 0);

                            tempOutputBuffer.AsSpan(0, numOutputBytes).CopyTo(output.Slice(outputLength));
                            outputLength += numOutputBytes;

                            currentInputIndex += numWholeBlocksInBytes;
                            bytesToWrite -= numWholeBlocksInBytes;
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(new Span<byte>(tempOutputBuffer, 0, numOutputBytes));
                            ArrayPool<byte>.Shared.Return(tempOutputBuffer);
                        }
                    }
                    else
                    {
                        // do it the slow way
                        numOutputBytes = transform.TransformBlock(buffer, currentInputIndex, _inputBlockSize, _outputBuffer, 0);

                        _outputBuffer.AsSpan(0, numOutputBytes).CopyTo(output.Slice(outputLength));
                        outputLength += numOutputBytes;

                        currentInputIndex += _inputBlockSize;
                        bytesToWrite -= _inputBlockSize;
                    }
                }
                else
                {
                    // In this case, we don't have an entire block's worth left, so store it up in the
                    // input buffer, which by now must be empty.
                    Buffer.BlockCopy(buffer, currentInputIndex, _inputBuffer, 0, bytesToWrite);
                    _inputBufferIndex += bytesToWrite;
                    break;
                }
            }

            byte[] finalBytes = transform.TransformFinalBlock(_inputBuffer, 0, _inputBufferIndex);
            finalBytes.AsSpan(0, finalBytes.Length).CopyTo(output.Slice(outputLength));
            return outputLength + finalBytes.Length;
        }

        private sealed class AesPooledPolicy : PooledObjectFactory<Aes>
        {
            private readonly byte[] _key;

            public AesPooledPolicy(byte[] key)
            {
                _key = key;
            }

            public override Aes Create()
            {
                var aes = Aes.Create();
                aes.Key = _key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                return aes;
            }
        }
    }
}
