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
    internal struct AesDecryption192Keys
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
    }
}
#endif