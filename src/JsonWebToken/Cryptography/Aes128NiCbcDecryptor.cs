// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class Aes128NiCbcDecryptor : AesDecryptor
    {
        private const int BlockSize = 16;

        private readonly Aes128DecryptionKeys _keys;

        public Aes128NiCbcDecryptor(ReadOnlySpan<byte> key)
        {
            _keys = new Aes128DecryptionKeys(key);
        }

        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        public override void DecryptBlock(ref byte ciphertext, ref byte plaintext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext);

            block = Sse2.Xor(block, _keys.Key0);
            block = Aes.Decrypt(block, _keys.Key1);
            block = Aes.Decrypt(block, _keys.Key2);
            block = Aes.Decrypt(block, _keys.Key3);
            block = Aes.Decrypt(block, _keys.Key4);
            block = Aes.Decrypt(block, _keys.Key5);
            block = Aes.Decrypt(block, _keys.Key6);
            block = Aes.Decrypt(block, _keys.Key7);
            block = Aes.Decrypt(block, _keys.Key8);
            block = Aes.Decrypt(block, _keys.Key9);
            block = Aes.DecryptLast(block, _keys.Key10);
            Unsafe.WriteUnaligned(ref plaintext, block);
        }

        public override unsafe bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            ref byte input = ref MemoryMarshal.GetReference(ciphertext);
            ref byte output = ref MemoryMarshal.GetReference(plaintext);
            Vector128<byte> state = default;
            var feedback = nonce.AsVector128<byte>();

            IntPtr offset = (IntPtr)0;
            while ((byte*)offset < (byte*)ciphertext.Length)
            {
                var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref input, offset));
                var lastIn = block;
                state = Sse2.Xor(block, _keys.Key0);

                state = Aes.Decrypt(state, _keys.Key1);
                state = Aes.Decrypt(state, _keys.Key2);
                state = Aes.Decrypt(state, _keys.Key3);
                state = Aes.Decrypt(state, _keys.Key4);
                state = Aes.Decrypt(state, _keys.Key5);
                state = Aes.Decrypt(state, _keys.Key6);
                state = Aes.Decrypt(state, _keys.Key7);
                state = Aes.Decrypt(state, _keys.Key8);
                state = Aes.Decrypt(state, _keys.Key9);
                state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key10, feedback));

                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref output, offset), state);

                feedback = lastIn;

                offset += BlockSize;
            }

            byte padding = Unsafe.AddByteOffset(ref output, offset - 1);
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