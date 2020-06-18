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
    internal sealed class Aes192NiCbcDecryptor : AesDecryptor
    {
        private readonly AesDecryption192Keys _keys;

        public Aes192NiCbcDecryptor(ReadOnlySpan<byte> key)
        {
            _keys = new AesDecryption192Keys(key);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Shuffle(Vector128<byte> left, Vector128<byte> right, byte control)
           => Sse2.Shuffle(left.AsDouble(), right.AsDouble(), control).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte control)
        {
            var keyGened = Aes.KeygenAssist(tmp3, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0x55).AsByte();
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, keyGened);
            keyGened = Sse2.Shuffle(tmp1.AsInt32(), 0xFF).AsByte();
            return Sse2.Xor(Sse2.Xor(tmp3, Sse2.ShiftLeftLogical128BitLane(tmp3, 4)), keyGened);
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
            block = Aes.Decrypt(block, _keys.Key10);
            block = Aes.Decrypt(block, _keys.Key11);
            block = Aes.DecryptLast(block, _keys.Key12);
            Unsafe.WriteUnaligned(ref plaintext, block);
        }

        public override unsafe bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            if (nonce.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.nonce, 16);
            }

            ref byte output = ref MemoryMarshal.GetReference(plaintext);
            Vector128<byte> state = default;
            if (!ciphertext.IsEmpty)
            {
                ref byte input = ref MemoryMarshal.GetReference(ciphertext);
                var feedback = nonce.AsVector128<byte>();
                ref byte inputEnd = ref Unsafe.AddByteOffset(ref input, (IntPtr)ciphertext.Length - BlockSize + 1);

                while (Unsafe.IsAddressLessThan(ref input, ref inputEnd))
                {
                    var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref input);
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
                    state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key12, feedback));

                    Unsafe.WriteUnaligned(ref output, state);

                    feedback = lastIn;

                    input = ref Unsafe.AddByteOffset(ref input, (IntPtr)BlockSize);
                    output = ref Unsafe.AddByteOffset(ref output, (IntPtr)BlockSize);
                }
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

        private struct AesDecryption192Keys
        {
            private const int Count = 13;

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

            public AesDecryption192Keys(ReadOnlySpan<byte> key)
            {
                if (key.Length < 24)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes192CbcHmacSha384, 192, key.Length * 8);
                }

                ref var keyRef = ref MemoryMarshal.GetReference(key);

                var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
                var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));
                Key12 = tmp1;

                var tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x01);
                Key11 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
                Key10 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

                tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x02);
                Key9 = Aes.InverseMixColumns(tmp1);

                tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x04);
                Key8 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
                Key7 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

                tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x08);
                Key6 = Aes.InverseMixColumns(tmp1);

                tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x10);
                Key5 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
                Key4 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

                tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x20);
                Key3 = Aes.InverseMixColumns(tmp1);

                tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x40);
                Key2 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
                Key1 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

                KeyGenAssist(ref tmp1, tmp4, 0x80);
                Key0 = tmp1;
            }

            public void Clear()
            {
                ref byte that = ref Unsafe.As<AesDecryption192Keys, byte>(ref Unsafe.AsRef(this));
                Unsafe.InitBlock(ref that, 0, Count * 16);
            }
        }
    }
}
#endif