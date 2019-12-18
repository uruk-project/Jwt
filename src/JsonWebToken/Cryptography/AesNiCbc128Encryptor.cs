// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class AesNiCbc128Encryptor : AesEncryptor
    {
        private readonly Aes128Keys _keys;

        private const int BlockSize = 16;

        public AesNiCbc128Encryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);
            _keys.Key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            _keys.Key1 = KeyGenAssist(_keys.Key0, 0x01);
            _keys.Key2 = KeyGenAssist(_keys.Key1, 0x02);
            _keys.Key3 = KeyGenAssist(_keys.Key2, 0x04);
            _keys.Key4 = KeyGenAssist(_keys.Key3, 0x08);
            _keys.Key5 = KeyGenAssist(_keys.Key4, 0x10);
            _keys.Key6 = KeyGenAssist(_keys.Key5, 0x20);
            _keys.Key7 = KeyGenAssist(_keys.Key6, 0x40);
            _keys.Key8 = KeyGenAssist(_keys.Key7, 0x80);
            _keys.Key9 = KeyGenAssist(_keys.Key8, 0x1B);
            _keys.Key10 = KeyGenAssist(_keys.Key9, 0x36);
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

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        /// <inheritsdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var ivRef = ref MemoryMarshal.GetReference(nonce);

            var state = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);
            ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)plaintext.Length - BlockSize + 1);

            while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
            {
                var src = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
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
                Unsafe.WriteUnaligned(ref outputRef, state);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)BlockSize);
            }

            int left = plaintext.Length & 15;

            // Reuse the destination buffer as last block buffer
            Unsafe.CopyBlockUnaligned(ref outputRef, ref inputRef, (uint)left);
            byte padding = (byte)(BlockSize - left);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)left), padding, padding);
            var srcLast = Unsafe.ReadUnaligned<Vector128<byte>>(ref outputRef);

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
            Unsafe.WriteUnaligned(ref outputRef, state);
        }


        /// <inheritsdoc />
        public void Encrypt3(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var nonceRef = ref MemoryMarshal.GetReference(nonce);

            var state = Unsafe.ReadUnaligned<Vector128<byte>>(ref nonceRef);
            ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)plaintext.Length - BlockSize + 1);

            while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
            {
                var src = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
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
                Unsafe.WriteUnaligned(ref outputRef, state);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)BlockSize);
            }

            int left = plaintext.Length & 15;

            // Reuse the destination buffer as last block buffer
            Unsafe.CopyBlockUnaligned(ref outputRef, ref inputRef, (uint)left);
            byte padding = (byte)(BlockSize - left);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref outputRef, (IntPtr)left), padding, padding);
            var srcLast = Unsafe.ReadUnaligned<Vector128<byte>>(ref outputRef);

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
            Unsafe.WriteUnaligned(ref outputRef, state);
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
    }
}
#endif