// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_SIMD
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace JsonWebToken.Cryptography
{
    internal readonly struct Aes128DecryptionKeys
    {
        private const int Count = 11;

        public readonly Vector128<byte> Key0;
        public readonly Vector128<byte> Key1;
        public readonly Vector128<byte> Key2;
        public readonly Vector128<byte> Key3;
        public readonly Vector128<byte> Key4;
        public readonly Vector128<byte> Key5;
        public readonly Vector128<byte> Key6;
        public readonly Vector128<byte> Key7;
        public readonly Vector128<byte> Key8;
        public readonly Vector128<byte> Key9;
        public readonly Vector128<byte> Key10;

        public Aes128DecryptionKeys(ReadOnlySpan<byte> key)
        {
            Debug.Assert(key.Length >= 16);

            var tmp = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(key));
            Key10 = tmp;

            tmp = KeyGenAssist(tmp, 0x01);
            Key9 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x02);
            Key8 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x04);
            Key7 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x08);
            Key6 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x10);
            Key5 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x20);
            Key4 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x40);
            Key3 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x80);
            Key2 = Aes.InverseMixColumns(tmp);
            tmp = KeyGenAssist(tmp, 0x1B);
            Key1 = Aes.InverseMixColumns(tmp);
            Key0 = KeyGenAssist(tmp, 0x36);
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

        public void Clear()
        {
            ref byte that = ref Unsafe.As<Aes128DecryptionKeys, byte>(ref Unsafe.AsRef(this));
            Unsafe.InitBlock(ref that, 0, Count * 16);
        }
    }
}
#endif