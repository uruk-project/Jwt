// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class Aes128NiCbcEncryptor : AesEncryptor
    {
        private readonly Aes128EncryptionKeys _keys;

        public Aes128NiCbcEncryptor(ReadOnlySpan<byte> key)
        {
            _keys = new Aes128EncryptionKeys(key);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        /// <inheritsdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            if (nonce.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.nonce, 16);
            }

            if (ciphertext.Length < GetCiphertextLength(plaintext.Length))
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.ciphertext, GetCiphertextLength(plaintext.Length));
            }

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

                    state = Sse2.Xor(src, _keys.Key0);
                    state = Aes.Encrypt(state, _keys.Key1);
                    state = Aes.Encrypt(state, _keys.Key2);
                    state = Aes.Encrypt(state, _keys.Key3);
                    state = Aes.Encrypt(state, _keys.Key4);
                    state = Aes.Encrypt(state, _keys.Key5);
                    state = Aes.Encrypt(state, _keys.Key6);
                    state = Aes.Encrypt(state, _keys.Key7);
                    state = Aes.Encrypt(state, _keys.Key8);
                    state = Aes.Encrypt(state, _keys.Key9);
                    state = Aes.EncryptLast(state, _keys.Key10);
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

            state = Sse2.Xor(srcLast, _keys.Key0);
            state = Aes.Encrypt(state, _keys.Key1);
            state = Aes.Encrypt(state, _keys.Key2);
            state = Aes.Encrypt(state, _keys.Key3);
            state = Aes.Encrypt(state, _keys.Key4);
            state = Aes.Encrypt(state, _keys.Key5);
            state = Aes.Encrypt(state, _keys.Key6);
            state = Aes.Encrypt(state, _keys.Key7);
            state = Aes.Encrypt(state, _keys.Key8);
            state = Aes.Encrypt(state, _keys.Key9);
            state = Aes.EncryptLast(state, _keys.Key10);
            Unsafe.WriteUnaligned(ref output, state);
        }

        public override void EncryptBlock(ref byte plaintext, ref byte ciphertext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref plaintext);

            block = Sse2.Xor(block, _keys.Key0);
            block = Aes.Encrypt(block, _keys.Key1);
            block = Aes.Encrypt(block, _keys.Key2);
            block = Aes.Encrypt(block, _keys.Key3);
            block = Aes.Encrypt(block, _keys.Key4);
            block = Aes.Encrypt(block, _keys.Key5);
            block = Aes.Encrypt(block, _keys.Key6);
            block = Aes.Encrypt(block, _keys.Key7);
            block = Aes.Encrypt(block, _keys.Key8);
            block = Aes.Encrypt(block, _keys.Key9);
            block = Aes.EncryptLast(block, _keys.Key10);
            Unsafe.WriteUnaligned(ref ciphertext, block);
        }

        internal readonly struct Aes128EncryptionKeys
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

            public Aes128EncryptionKeys(ReadOnlySpan<byte> key)
            {
                if (key.Length < 16)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
                }

                Key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));
                Key1 = KeyGenAssist(Key0, 0x01);
                Key2 = KeyGenAssist(Key1, 0x02);
                Key3 = KeyGenAssist(Key2, 0x04);
                Key4 = KeyGenAssist(Key3, 0x08);
                Key5 = KeyGenAssist(Key4, 0x10);
                Key6 = KeyGenAssist(Key5, 0x20);
                Key7 = KeyGenAssist(Key6, 0x40);
                Key8 = KeyGenAssist(Key7, 0x80);
                Key9 = KeyGenAssist(Key8, 0x1B);
                Key10 = KeyGenAssist(Key9, 0x36);
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
                ref byte that = ref Unsafe.As<Aes128EncryptionKeys, byte>(ref Unsafe.AsRef(this));
                Unsafe.InitBlock(ref that, 0, Count * 16);
            }
        }
    }
}
#endif