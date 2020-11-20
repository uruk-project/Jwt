// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Cryptography
{
    internal sealed class Aes128CbcDecryptor : AesDecryptor
    {
        public override unsafe bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            if (nonce.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.nonce, 16);
            }

            ref byte output = ref MemoryMarshal.GetReference(plaintext);
            Vector128<byte> state = default;
            if (!ciphertext.IsEmpty)
            {
                var keys = new Aes128DecryptionKeys(key);
                ref byte input = ref MemoryMarshal.GetReference(ciphertext);
                var feedback = nonce.AsVector128<byte>();
                ref byte inputEnd = ref Unsafe.AddByteOffset(ref input, (IntPtr)ciphertext.Length - BlockSize + 1);

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
                        state = Aes.DecryptLast(state, Sse2.Xor(keys.Key10, feedback));

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
            }

            int left = plaintext.Length & BlockSize - 1;


        Invalid:
            bytesWritten = 0;
            return false;
        }

        private readonly struct Aes128DecryptionKeys
        {
            private const int Count = 11;

            public readonly Vector128<byte> Key0;
            public readonly Vector128<byte> Key1;
            public readonly Vector128<byte> Key2;
            public readonly Vector128<byte> Key3;
            public readonly Vector128<byte> Key4;
            public readonly Vector128<byte> Key5;
            public readonly Vector128<byte> Key6;
            public readonly Vector128<byte> Key7;
            public readonly Vector128<byte> Key8;
            public readonly Vector128<byte> Key9;
            public readonly Vector128<byte> Key10;

            public Aes128DecryptionKeys(ReadOnlySpan<byte> key)
            {
                if (key.Length < 16)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
                }

                var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));
                Key10 = tmp;

                tmp = KeyGenAssist(tmp, 0x01);
                Key9 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x02);
                Key8 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x04);
                Key7 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x08);
                Key6 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x10);
                Key5 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x20);
                Key4 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x40);
                Key3 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x80);
                Key2 = Aes.InverseMixColumns(tmp);
                tmp = KeyGenAssist(tmp, 0x1B);
                Key1 = Aes.InverseMixColumns(tmp);
                Key0 = KeyGenAssist(tmp, 0x36);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
            {
                var keyGened = Aes.KeygenAssist(key, control);
                keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
                key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
                return Sse2.Xor(key, keyGened);
            }

            public void Clear()
            {
                ref byte that = ref Unsafe.As<Aes128DecryptionKeys, byte>(ref Unsafe.AsRef(this));
                Unsafe.InitBlock(ref that, 0, Count * 16);
            }
        }
    }
}
#endif