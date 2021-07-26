﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Cryptography
{
    internal sealed class Aes192CbcDecryptor : AesDecryptor
    {
        public override unsafe bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            Debug.Assert(ciphertext.Length % BlockSize == 0);
            if (nonce.Length != 16)
            {
                goto Invalid;
            }

            if (ciphertext.IsEmpty)
            {
                goto Invalid;
            }

            ref byte output = ref MemoryMarshal.GetReference(plaintext);
#if NET5_0_OR_GREATER
            Vector128<byte> state;
            Unsafe.SkipInit(out state);
#else
            Vector128<byte> state = default;
#endif
            ref byte input = ref MemoryMarshal.GetReference(ciphertext);
            var feedback = nonce.AsVector128<byte>();
            ref byte inputEnd = ref Unsafe.AddByteOffset(ref input, (IntPtr)ciphertext.Length - BlockSize + 1);

            var keys = new Aes192DecryptionKeys(key);
            try
            {
                while (Unsafe.IsAddressLessThan(ref input, ref inputEnd))
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref input);
                    var lastIn = block;
                    state = Sse2.Xor(block, keys.Key0);

                    state = Aes.Decrypt(state, keys.Key1);
                    state = Aes.Decrypt(state, keys.Key2);
                    state = Aes.Decrypt(state, keys.Key3);
                    state = Aes.Decrypt(state, keys.Key4);
                    state = Aes.Decrypt(state, keys.Key5);
                    state = Aes.Decrypt(state, keys.Key6);
                    state = Aes.Decrypt(state, keys.Key7);
                    state = Aes.Decrypt(state, keys.Key8);
                    state = Aes.Decrypt(state, keys.Key9);
                    state = Aes.Decrypt(state, keys.Key10);
                    state = Aes.Decrypt(state, keys.Key11);
                    state = Aes.DecryptLast(state, Sse2.Xor(keys.Key12, feedback));

                    Unsafe.WriteUnaligned(ref output, state);

                    feedback = lastIn;

                    input = ref Unsafe.AddByteOffset(ref input, (IntPtr)BlockSize);
                    output = ref Unsafe.AddByteOffset(ref output, (IntPtr)BlockSize);
                }
            }
            finally
            {
                keys.Clear();
            }

            byte padding = Unsafe.SubtractByteOffset(ref output, (IntPtr)1);
            if (padding > BlockSize)
            {
                goto Invalid;
            }

            var mask = GetPaddingMask(padding);
            if (!Sse2.And(mask, state).Equals(mask))
            {
                goto Invalid;
            }

            bytesWritten = ciphertext.Length - padding;
            return true;

        Invalid:
            bytesWritten = 0;
            return false;
        }
    }
}
#endif