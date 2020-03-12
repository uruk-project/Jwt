// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class Aes256NiCbcDecryptor : AesDecryptor
    {
        private const int BlockSize = 16;

        private readonly Aes256DecryptionKeys _keys;

        public Aes256NiCbcDecryptor(ReadOnlySpan<byte> key)
        {
            _keys = new Aes256DecryptionKeys(key);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
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
                state = Aes.Decrypt(state, _keys.Key10);
                state = Aes.Decrypt(state, _keys.Key11);
                state = Aes.Decrypt(state, _keys.Key12);
                state = Aes.Decrypt(state, _keys.Key13);
                state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key14, feedback));

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
            block = Aes.Decrypt(block, _keys.Key10);
            block = Aes.Decrypt(block, _keys.Key11);
            block = Aes.Decrypt(block, _keys.Key12);
            block = Aes.Decrypt(block, _keys.Key13);
            block = Aes.DecryptLast(block, _keys.Key14);
            Unsafe.WriteUnaligned(ref plaintext, block);
        }

        private struct Aes256DecryptionKeys
        {
            private const int Count = 15;

            public Vector128<byte> Key0;
            public Vector128<byte> Key1;
            public Vector128<byte> Key2;
            public Vector128<byte> Key3;
            public Vector128<byte> Key4;
            public Vector128<byte> Key5;
            public Vector128<byte> Key6;
            public Vector128<byte> Key7;
            public Vector128<byte> Key8;
            public Vector128<byte> Key9;
            public Vector128<byte> Key10;
            public Vector128<byte> Key11;
            public Vector128<byte> Key12;
            public Vector128<byte> Key13;
            public Vector128<byte> Key14;

            public Aes256DecryptionKeys(ReadOnlySpan<byte> key)
            {
                if (key.Length != 32)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes256CbcHmacSha512, 256, key.Length * 8);
                }

                ref var keyRef = ref MemoryMarshal.GetReference(key);

                var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
                var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref keyRef, (IntPtr)16));
                Key14 = tmp1;
                Key13 = Aes.InverseMixColumns(tmp3);

                KeyGenAssist1(ref tmp1, tmp3, 0x01);
                Key12 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key11 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x02);
                Key10 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key9 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x04);
                Key8 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key7 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x08);
                Key6 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key5 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x10);
                Key4 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key3 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x20);
                Key2 = Aes.InverseMixColumns(tmp1);
                KeyGenAssist2(tmp1, ref tmp3);
                Key1 = Aes.InverseMixColumns(tmp3);
                KeyGenAssist1(ref tmp1, tmp3, 0x40);
                Key0 = (tmp1);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void KeyGenAssist1(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte control)
            {
                var keyGened = Aes.KeygenAssist(tmp3, control);
                keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
                tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
                tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
                tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
                tmp1 = Sse2.Xor(tmp1, keyGened);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void KeyGenAssist2(Vector128<byte> tmp1, ref Vector128<byte> tmp3)
            {
                var keyGened = Aes.KeygenAssist(tmp1, 0);
                var tmp2 = Sse2.Shuffle(keyGened.AsInt32(), 0xAA).AsByte();
                tmp3 = Sse2.Xor(tmp3, Sse2.ShiftLeftLogical128BitLane(tmp3, 4));
                tmp3 = Sse2.Xor(tmp3, Sse2.ShiftLeftLogical128BitLane(tmp3, 4));
                tmp3 = Sse2.Xor(tmp3, Sse2.ShiftLeftLogical128BitLane(tmp3, 4));
                tmp3 = Sse2.Xor(tmp3, tmp2);
            }

            public void Clear()
            {
                ref byte that = ref Unsafe.As<Aes256DecryptionKeys, byte>(ref Unsafe.AsRef(this));
                Unsafe.InitBlock(ref that, 0, Count * 16);
            }
        }
    }
}
#endif