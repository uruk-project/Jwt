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
    internal sealed class AesNiCbc128Decryptor : AesDecryptor
    {
        private const int BlockSize = 16;

        private readonly Aes128Keys _keys;

        public AesNiCbc128Decryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes128CbcHmacSha256, 128, key.Length * 8);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);

            var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            _keys.Key10 = tmp;

            tmp = KeyGenAssist(tmp, 0x01);
            _keys.Key9 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x02);
            _keys.Key8 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x04);
            _keys.Key7 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x08);
            _keys.Key6 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x10);
            _keys.Key5 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x20);
            _keys.Key4 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x40);
            _keys.Key3 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x80);
            _keys.Key2 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x1B);
            _keys.Key1 = Aes.InverseMixColumns(tmp);
            _keys.Key0 = KeyGenAssist(tmp, 0x36);
        }

        public override void Dispose()
        {
            // Clear the keys
            _keys.Clear();
        }

        public override unsafe void DecryptBlock(ref byte ciphertext, ref byte plaintext)
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

        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var ivRef = ref MemoryMarshal.GetReference(nonce);
            Vector128<byte> state = default;
            var feedback = Unsafe.ReadUnaligned<Vector128<byte>>(ref ivRef);

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
                state = Aes.DecryptLast(state, Sse2.Xor(_keys.Key10, feedback));

                Unsafe.WriteUnaligned(ref outputRef, state);

                feedback = lastIn;

                inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
            }

            ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
            byte padding = paddingRef;
            var mask = Vector128.Create(padding);
            mask = Sse2.ShiftLeftLogical128BitLane(mask, (byte)(BlockSize - padding));

            if (!Sse2.And(mask, state).Equals(mask))
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = ciphertext.Length - paddingRef;
            return true;
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
    }
}
#endif