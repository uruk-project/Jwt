// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken
{
    internal sealed class Aes192CbcEncryptor : AesEncryptor
    {
        /// <inheritsdoc />
        public override void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            if (nonce.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.nonce, 16);
            }

            if (ciphertext.Length < GetCiphertextLength(plaintext.Length))
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.ciphertext, GetCiphertextLength(plaintext.Length));
            }

            var keys = new AesEncryption192Keys(key);
            var state = nonce.AsVector128<byte>();
            int left = plaintext.Length & BlockSize - 1;
            ref byte output = ref MemoryMarshal.GetReference(ciphertext);
            if (!plaintext.IsEmpty)
            {
                ref byte input = ref MemoryMarshal.GetReference(plaintext);
                ref byte inputEnd = ref Unsafe.AddByteOffset(ref input, (IntPtr)plaintext.Length - BlockSize + 1);

                while (Unsafe.IsAddressLessThan(ref input, ref inputEnd))
                {
                    var src = Unsafe.ReadUnaligned<Vector128<byte>>(ref input);
                    src = Sse2.Xor(src, state);

                    state = Sse2.Xor(src, keys.Key0);
                    state = Aes.Encrypt(state, keys.Key1);
                    state = Aes.Encrypt(state, keys.Key2);
                    state = Aes.Encrypt(state, keys.Key3);
                    state = Aes.Encrypt(state, keys.Key4);
                    state = Aes.Encrypt(state, keys.Key5);
                    state = Aes.Encrypt(state, keys.Key6);
                    state = Aes.Encrypt(state, keys.Key7);
                    state = Aes.Encrypt(state, keys.Key8);
                    state = Aes.Encrypt(state, keys.Key9);
                    state = Aes.Encrypt(state, keys.Key10);
                    state = Aes.Encrypt(state, keys.Key11);
                    state = Aes.EncryptLast(state, keys.Key12);
                    Unsafe.WriteUnaligned(ref output, state);

                    input = ref Unsafe.AddByteOffset(ref input, (IntPtr)BlockSize);
                    output = ref Unsafe.AddByteOffset(ref output, (IntPtr)BlockSize);
                }

                // Reuse the destination buffer as last block buffer
                Unsafe.CopyBlockUnaligned(ref output, ref input, (uint)left);
            }

            byte padding = (byte)(BlockSize - left);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref output, (IntPtr)left), padding, padding);
            var srcLast = Unsafe.ReadUnaligned<Vector128<byte>>(ref output);

            srcLast = Sse2.Xor(srcLast, state);

            state = Sse2.Xor(srcLast, keys.Key0);
            state = Aes.Encrypt(state, keys.Key1);
            state = Aes.Encrypt(state, keys.Key2);
            state = Aes.Encrypt(state, keys.Key3);
            state = Aes.Encrypt(state, keys.Key4);
            state = Aes.Encrypt(state, keys.Key5);
            state = Aes.Encrypt(state, keys.Key6);
            state = Aes.Encrypt(state, keys.Key7);
            state = Aes.Encrypt(state, keys.Key8);
            state = Aes.Encrypt(state, keys.Key9);
            state = Aes.Encrypt(state, keys.Key10);
            state = Aes.Encrypt(state, keys.Key11);
            state = Aes.EncryptLast(state, keys.Key12);
            Unsafe.WriteUnaligned(ref output, state);
        }
    } 
}
#endif