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
    internal sealed class AesNiCbc256Decryptor : AesDecryptor
    {
        private const int BlockSize = 16;

        private readonly Aes256Keys _keys;

        public AesNiCbc256Decryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length != 32)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes256CbcHmacSha512, 256, key.Length * 8);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);

            var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref keyRef, (IntPtr)16));
            _keys.Key14 = tmp1;
            _keys.Key13 = Aes.InverseMixColumns(tmp3);

            KeyGenAssist1(ref tmp1, tmp3, 0x01);
            _keys.Key12 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key11 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x02);
            _keys.Key10 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key9 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x04);
            _keys.Key8 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key7 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x08);
            _keys.Key6 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key5 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x10);
            _keys.Key4 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key3 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x20);
            _keys.Key2 = Aes.InverseMixColumns(tmp1);
            KeyGenAssist2(tmp1, ref tmp3);
            _keys.Key1 = Aes.InverseMixColumns(tmp3);
            KeyGenAssist1(ref tmp1, tmp3, 0x40);
            _keys.Key0 = (tmp1);
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

        /// <inheritsdoc />
        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var ivRef = ref MemoryMarshal.GetReference(nonce);

            var feedback = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);
            Vector128<byte> state = default;
            ref var inputEndRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr)ciphertext.Length);
            while (Unsafe.IsAddressLessThan(ref inputRef, ref inputEndRef))
            {
                var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref inputRef);
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

                Unsafe.WriteUnaligned(ref outputRef, state);

                feedback = lastIn;

                inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
            }

            ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
            byte padding = paddingRef;
            var mask = Vector128.Create(padding);
            mask = Sse2.ShiftLeftLogical128BitLane(mask, (byte)(16 - padding));

            if (!Sse2.And(mask, state).Equals(mask))
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = ciphertext.Length - paddingRef;
            return true;
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
    }
}
#endif