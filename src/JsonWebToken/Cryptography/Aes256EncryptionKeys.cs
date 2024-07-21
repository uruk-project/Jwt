// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Cryptography
{
    internal struct Aes256EncryptionKeys
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

        public Aes256EncryptionKeys(ReadOnlySpan<byte> key)
        {
            if (key.Length < 32)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(EncryptionAlgorithm.A256CbcHS512, 256, key.Length * 8);
            }

            ref var keyRef = ref MemoryMarshal.GetReference(key);
            var tmp1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref keyRef);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));
            Key0 = tmp1;
            Key1 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x01);
            Key2 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key3 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x02);
            Key4 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key5 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x04);
            Key6 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key7 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x08);
            Key8 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key9 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x10);
            Key10 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key11 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x20);
            Key12 = tmp1;
            KeyGenAssist2(tmp1, ref tmp3);
            Key13 = tmp3;
            KeyGenAssist1(ref tmp1, tmp3, 0x40);
            Key14 = tmp1;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void KeyGenAssist1(ref Vector128<byte> tmp1, Vector128<byte> tmp3, [ConstantExpected] byte control)
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
            ref byte that = ref Unsafe.As<Aes256EncryptionKeys, byte>(ref Unsafe.AsRef(in this));
            Unsafe.InitBlock(ref that, 0, Count * 16);
        }
    }
}
#endif