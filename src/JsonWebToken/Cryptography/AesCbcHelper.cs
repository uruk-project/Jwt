// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal static class AesCbcHelper
    {
        // Taken from https://github.com/dotnet/runtime/blob/master/src/libraries/System.Security.Cryptography.Primitives/src/System/Security/Cryptography/CryptoStream.cs#L516
        public static int Transform(ICryptoTransform transform, ReadOnlySpan<byte> input, int inputOffset, int inputLength, Span<byte> output)
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
                        byte[] tempOutputBuffer = ArrayPool<byte>.Shared.Rent(numWholeBlocksInBytes);

                        Span<byte> outputSpan = default;
                        try
                        {
                            numOutputBytes = transform.TransformBlock(buffer, currentInputIndex, numWholeBlocksInBytes, tempOutputBuffer, 0);

                            outputSpan = tempOutputBuffer.AsSpan(0, numOutputBytes);
                            outputSpan.CopyTo(output.Slice(outputLength));
                            outputLength += numOutputBytes;

                            currentInputIndex += numWholeBlocksInBytes;
                            bytesToWrite -= numWholeBlocksInBytes;
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(outputSpan);
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
            finalBytes.AsSpan().CopyTo(output.Slice(outputLength));
            return outputLength + finalBytes.Length;
        }
    }
}
