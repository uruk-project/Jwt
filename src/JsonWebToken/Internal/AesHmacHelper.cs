// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace JsonWebToken.Internal
{
    internal static class AesHmacHelper
    {
        public static void ComputeAuthenticationTag(Signer signer, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> authenticationTag)
        {
            byte[]? arrayToReturnToPool = null;
            try
            {
                int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
                Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                    ? stackalloc byte[macLength]
                    : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);

                associatedData.CopyTo(macBytes);
                iv.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + iv.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + iv.Length + ciphertext.Length), associatedData.Length * 8);

                signer.TrySign(macBytes, authenticationTag, out int writtenBytes);
                Debug.Assert(writtenBytes == authenticationTag.Length);
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

        public static  bool VerifyAuthenticationTag(Signer signer, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            byte[]? byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                iv.CopyTo(macBytes.Slice(associatedData.Length));
                ciphertext.CopyTo(macBytes.Slice(associatedData.Length + iv.Length));
                BinaryPrimitives.WriteInt64BigEndian(macBytes.Slice(associatedData.Length + iv.Length + ciphertext.Length), associatedData.Length << 3);
                if (!signer.Verify(macBytes, authenticationTag))
                {
                    return false;
                }
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }

            return true;
        }
    }
}
