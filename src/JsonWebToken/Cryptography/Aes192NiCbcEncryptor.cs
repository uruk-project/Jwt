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
    internal sealed class Aes192NiCbcEncryptor : AesEncryptor
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
    
    internal sealed class Aes192NiBlockEncryptor : AesBlockEncryptor
    {
        private readonly AesEncryption192Keys _keys;

        public Aes192NiBlockEncryptor(ReadOnlySpan<byte> key)
        {
            _keys = new AesEncryption192Keys(key);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
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
            block = Aes.Encrypt(block, _keys.Key10);
            block = Aes.Encrypt(block, _keys.Key11);
            block = Aes.EncryptLast(block, _keys.Key12);
            Unsafe.WriteUnaligned(ref ciphertext, block);
        }
    }

    internal struct AesEncryption192Keys
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

        public AesEncryption192Keys(ReadOnlySpan<byte> key)
        {
            if (key.Length < 24)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes192CbcHmacSha384, 192, key.Length * 8);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);

            var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));
            Key0 = tmp1;
            Key1 = tmp3;

            var tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x01);
            Key1 = Shuffle(tmp3, tmp1, 0);
            Key2 = Shuffle(tmp1, tmp4, 1);

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x02);
            Key3 = tmp1;

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x04);
            Key4 = Shuffle(tmp3, tmp1, 0);
            Key5 = Shuffle(tmp1, tmp4, 1);

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x08);
            Key6 = tmp1;

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x10);
            Key7 = Shuffle(tmp3, tmp1, 0);
            Key8 = Shuffle(tmp1, tmp4, 1);

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x20);
            Key9 = tmp1;

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x40);
            Key10 = Shuffle(tmp3, tmp1, 0);
            Key11 = Shuffle(tmp1, tmp4, 1);

            KeyGenAssist(ref tmp1, tmp4, 0x80);
            Key12 = tmp1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Shuffle(Vector128<byte> left, Vector128<byte> right, byte control)
           => Sse2.Shuffle(left.AsDouble(), right.AsDouble(), control).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte control)
        {
            var keyGened = Aes.KeygenAssist(tmp3, control);
            keyGened = Sse2.Shuffle(keyGened.AsInt32(), 0x55).AsByte();
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, Sse2.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Sse2.Xor(tmp1, keyGened);
            keyGened = Sse2.Shuffle(tmp1.AsInt32(), 0xFF).AsByte();
            return Sse2.Xor(Sse2.Xor(tmp3, Sse2.ShiftLeftLogical128BitLane(tmp3, 4)), keyGened);
        }

        public void Clear()
        {
            ref byte that = ref Unsafe.As<AesEncryption192Keys, byte>(ref Unsafe.AsRef(this));
            Unsafe.InitBlock(ref that, 0, Count * 16);
        }
    }
}
#endif