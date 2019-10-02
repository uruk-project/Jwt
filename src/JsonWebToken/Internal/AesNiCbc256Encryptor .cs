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
    public sealed class AesNiCbc256Encryptor : AesEncryptor
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
        private Vector128<byte> _key11;
        private Vector128<byte> _key12;
        private Vector128<byte> _key13;
        private Vector128<byte> _key14;

        public AesNiCbc256Encryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length < 24)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes192CbcHmacSha384, 386, key.Length << 3);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);
            var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));
            _key0 = tmp1;
            _key1 = tmp3;
            _key2 = KeyGenAssist1(ref tmp1, tmp3, 0x01);
            _key3 = KeyGenAssist2(tmp1, ref tmp3);
            _key4 = KeyGenAssist1(ref tmp1, tmp3, 0x02);
            _key5 = KeyGenAssist2(tmp1, ref tmp3);
            _key6 = KeyGenAssist1(ref tmp1, tmp3, 0x04);
            _key7 = KeyGenAssist2(tmp1, ref tmp3);
            _key8 = KeyGenAssist1(ref tmp1, tmp3, 0x08);
            _key9 = KeyGenAssist2(tmp1, ref tmp3);
            _key10 = KeyGenAssist1(ref tmp1, tmp3, 0x10);
            _key11 = KeyGenAssist2(tmp1, ref tmp3);
            _key12 = KeyGenAssist1(ref tmp1, tmp3, 0x20);
            _key13 = KeyGenAssist2(tmp1, ref tmp3);
            _key14 = KeyGenAssist1(ref tmp1, tmp3, 0x40);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist1(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte control)
        {
            var keyGened = Aes.KeygenAssist(tmp3, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0xAA).AsByte();
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            return Aes.Xor(tmp1, keyGened);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist2(Vector128<byte> tmp1, ref Vector128<byte> tmp3)
        {
            var keyGened = Aes.KeygenAssist(tmp1, 0);
            var tmp2 = Aes.Shuffle(keyGened.AsInt32(), 0xFF).AsByte();
            tmp3 = Aes.Xor(tmp3, Aes.ShiftLeftLogical128BitLane(tmp3, 4));
            tmp3 = Aes.Xor(tmp3, Aes.ShiftLeftLogical128BitLane(tmp3, 4));
            tmp3 = Aes.Xor(tmp3, Aes.ShiftLeftLogical128BitLane(tmp3, 4));
            return Aes.Xor(tmp3, tmp2);
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
            _key11 = Vector128<byte>.Zero;
            _key12 = Vector128<byte>.Zero;
            _key13 = Vector128<byte>.Zero;
            _key14 = Vector128<byte>.Zero;
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
                state = Aes.Encrypt(state, _key10);
                state = Aes.Encrypt(state, _key11);
                state = Aes.Encrypt(state, _key12);
                state = Aes.Encrypt(state, _key13);
                state = Aes.EncryptLast(state, _key14);
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
            state = Aes.Encrypt(state, _key10);
            state = Aes.Encrypt(state, _key11);
            state = Aes.Encrypt(state, _key12);
            state = Aes.Encrypt(state, _key13);
            state = Aes.EncryptLast(state, _key14);
            Unsafe.WriteUnaligned(ref outputRef, state);
        }
    }
}
#endif