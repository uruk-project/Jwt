// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Internal
{
    internal sealed class AesNiCbc128Encryptor : AesEncryptor
    {
        private const int BlockSize = 16;

        private Vector128<byte> _key0;
        private Vector128<byte> _key1;
        private Vector128<byte> _key2;
        private Vector128<byte> _key3;
        private Vector128<byte> _key4;
        private Vector128<byte> _key5;
        private Vector128<byte> _key6;
        private Vector128<byte> _key7;
        private Vector128<byte> _key8;
        private Vector128<byte> _key9;
        private Vector128<byte> _key10;

        public AesNiCbc128Encryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 256, 16);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);
            _key0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            _key1 = KeyGenAssist(_key0, 0x01);
            _key2 = KeyGenAssist(_key1, 0x02);
            _key3 = KeyGenAssist(_key2, 0x04);
            _key4 = KeyGenAssist(_key3, 0x08);
            _key5 = KeyGenAssist(_key4, 0x10);
            _key6 = KeyGenAssist(_key5, 0x20);
            _key7 = KeyGenAssist(_key6, 0x40);
            _key8 = KeyGenAssist(_key7, 0x80);
            _key9 = KeyGenAssist(_key8, 0x1B);
            _key10 = KeyGenAssist(_key9, 0x36);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(Vector128<byte> key, byte control)
        {
            var keyGened = Aes.KeygenAssist(key, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Aes.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            return Aes.Xor(key, keyGened);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _key0 = Vector128<byte>.Zero;
            _key1 = Vector128<byte>.Zero;
            _key2 = Vector128<byte>.Zero;
            _key3 = Vector128<byte>.Zero;
            _key4 = Vector128<byte>.Zero;
            _key5 = Vector128<byte>.Zero;
            _key6 = Vector128<byte>.Zero;
            _key7 = Vector128<byte>.Zero;
            _key8 = Vector128<byte>.Zero;
            _key9 = Vector128<byte>.Zero;
            _key10 = Vector128<byte>.Zero;
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
                src = Aes.Xor(src, state);

                state = Aes.Xor(src, _key0);
                state = Aes.Encrypt(state, _key1);
                state = Aes.Encrypt(state, _key2);
                state = Aes.Encrypt(state, _key3);
                state = Aes.Encrypt(state, _key4);
                state = Aes.Encrypt(state, _key5);
                state = Aes.Encrypt(state, _key6);
                state = Aes.Encrypt(state, _key7);
                state = Aes.Encrypt(state, _key8);
                state = Aes.Encrypt(state, _key9);
                state = Aes.EncryptLast(state, _key10);
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

            srcLast = Aes.Xor(srcLast, state);

            state = Aes.Xor(srcLast, _key0);
            state = Aes.Encrypt(state, _key1);
            state = Aes.Encrypt(state, _key2);
            state = Aes.Encrypt(state, _key3);
            state = Aes.Encrypt(state, _key4);
            state = Aes.Encrypt(state, _key5);
            state = Aes.Encrypt(state, _key6);
            state = Aes.Encrypt(state, _key7);
            state = Aes.Encrypt(state, _key8);
            state = Aes.Encrypt(state, _key9);
            state = Aes.EncryptLast(state, _key10);
            Unsafe.WriteUnaligned(ref outputRef, state);
        }

        public override void EncryptBlock(ref byte plaintext, ref byte ciphertext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref plaintext);

            block = Aes.Xor(block, _key0);
            block = Aes.Encrypt(block, _key1);
            block = Aes.Encrypt(block, _key2);
            block = Aes.Encrypt(block, _key3);
            block = Aes.Encrypt(block, _key4);
            block = Aes.Encrypt(block, _key5);
            block = Aes.Encrypt(block, _key6);
            block = Aes.Encrypt(block, _key7);
            block = Aes.Encrypt(block, _key8);
            block = Aes.Encrypt(block, _key9);
            block = Aes.EncryptLast(block, _key10);
            Unsafe.WriteUnaligned(ref ciphertext, block);
        }
    }
}
#endif