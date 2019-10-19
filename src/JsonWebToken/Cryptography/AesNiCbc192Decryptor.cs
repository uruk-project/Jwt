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
    internal sealed class AesNiCbc192Decryptor : AesDecryptor
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

        public AesNiCbc192Decryptor(ReadOnlySpan<byte> key)
        {
            if (key.Length != 24)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.Aes192CbcHmacSha384, 386, key.Length << 3);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);

            var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));
            _key12 = tmp1;

            var tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x01);
            _key11 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
            _key10 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x02);
            _key9 = Aes.InverseMixColumns(tmp1);

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x04);
            _key8 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
            _key7 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x08);
            _key6 = Aes.InverseMixColumns(tmp1);

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x10);
            _key5 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
            _key4 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

            tmp3 = KeyGenAssist(ref tmp1, tmp4, 0x20);
            _key3 = Aes.InverseMixColumns(tmp1);

            tmp4 = KeyGenAssist(ref tmp1, tmp3, 0x40);
            _key2 = Aes.InverseMixColumns(Shuffle(tmp3, tmp1, 0));
            _key1 = Aes.InverseMixColumns(Shuffle(tmp1, tmp4, 1));

            KeyGenAssist(ref tmp1, tmp4, 0x80);
            _key0 = tmp1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Shuffle(Vector128<byte> left, Vector128<byte> right, byte control)
           => Aes.Shuffle(left.AsDouble(), right.AsDouble(), control).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeyGenAssist(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte control)
        {
            var keyGened = Aes.KeygenAssist(tmp3, control);
            keyGened = Aes.Shuffle(keyGened.AsInt32(), 0x55).AsByte();
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Aes.Xor(tmp1, Aes.ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Aes.Xor(tmp1, keyGened);
            keyGened = Aes.Shuffle(tmp1.AsInt32(), 0xFF).AsByte();
            return Aes.Xor(Aes.Xor(tmp3, Aes.ShiftLeftLogical128BitLane(tmp3, 4)), keyGened);
        }

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
        }

        public override void DecryptBlock(ref byte ciphertext, ref byte plaintext)
        {
            var block = Unsafe.ReadUnaligned<Vector128<byte>>(ref ciphertext);

            block = Aes.Xor(block, _key0);
            block = Aes.Decrypt(block, _key1);
            block = Aes.Decrypt(block, _key2);
            block = Aes.Decrypt(block, _key3);
            block = Aes.Decrypt(block, _key4);
            block = Aes.Decrypt(block, _key5);
            block = Aes.Decrypt(block, _key6);
            block = Aes.Decrypt(block, _key7);
            block = Aes.Decrypt(block, _key8);
            block = Aes.Decrypt(block, _key9);
            block = Aes.Decrypt(block, _key10);
            block = Aes.Decrypt(block, _key11);
            block = Aes.DecryptLast(block, _key12);
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
                state = Aes.Xor(block, _key0);

                state = Aes.Decrypt(state, _key1);
                state = Aes.Decrypt(state, _key2);
                state = Aes.Decrypt(state, _key3);
                state = Aes.Decrypt(state, _key4);
                state = Aes.Decrypt(state, _key5);
                state = Aes.Decrypt(state, _key6);
                state = Aes.Decrypt(state, _key7);
                state = Aes.Decrypt(state, _key8);
                state = Aes.Decrypt(state, _key9);
                state = Aes.Decrypt(state, _key10);
                state = Aes.Decrypt(state, _key11);
                state = Aes.DecryptLast(state, Aes.Xor(_key12, feedback));

                Unsafe.WriteUnaligned(ref outputRef, state);

                feedback = lastIn;

                inputRef = ref Unsafe.Add(ref inputRef, (IntPtr)BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, (IntPtr)BlockSize);
            }

            ref byte paddingRef = ref Unsafe.Subtract(ref outputRef, 1);
            byte padding = paddingRef;
            var mask = Vector128.Create(padding);
            mask = Aes.ShiftLeftLogical128BitLane(mask, (byte)(16 - padding));

            if (!Aes.And(mask, state).Equals(mask))
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = ciphertext.Length - paddingRef;
            return true;
        }
    }
}
#endif