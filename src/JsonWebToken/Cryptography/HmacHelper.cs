// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
#if SUPPORT_SIMD
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    internal static class HmacHelper
    {
        public static void InitializeIOKeys(ReadOnlySpan<byte> key, Span<byte> keys, int blockSize)
        {
#if SUPPORT_SIMD
            if (Avx2.IsSupported && key.Length != 0 && (key.Length & 31) == 0)
            {
                Vector256<byte> innerKeyInit = Vector256.Create((byte)0x36);
                Vector256<byte> outerKeyInit = Vector256.Create((byte)0x5c);

                ref byte keyRef = ref MemoryMarshal.GetReference(key);
                ref byte keyEndRef = ref Unsafe.Add(ref keyRef, key.Length);
                ref byte innerKeyRef = ref Unsafe.AsRef(keys[0]);
                ref byte outerKeyRef = ref Unsafe.Add(ref innerKeyRef, blockSize);
                ref byte innerKeyEndRef = ref outerKeyRef;
                do
                {
                    var k1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref keyRef);
                    Unsafe.WriteUnaligned(ref innerKeyRef, Avx2.Xor(k1, innerKeyInit));
                    Unsafe.WriteUnaligned(ref outerKeyRef, Avx2.Xor(k1, outerKeyInit));

                    // assume the IO keys are Modulo 32
                    keyRef = ref Unsafe.Add(ref keyRef, 32);
                    innerKeyRef = ref Unsafe.Add(ref innerKeyRef, 32);
                    outerKeyRef = ref Unsafe.Add(ref outerKeyRef, 32);
                } while (Unsafe.IsAddressLessThan(ref keyRef, ref keyEndRef));

                // treat the remain
                while (Unsafe.IsAddressLessThan(ref innerKeyRef, ref innerKeyEndRef))
                {
                    Unsafe.WriteUnaligned(ref innerKeyRef, innerKeyInit);
                    Unsafe.WriteUnaligned(ref outerKeyRef, outerKeyInit);
                    innerKeyRef = ref Unsafe.Add(ref innerKeyRef, 32);
                    outerKeyRef = ref Unsafe.Add(ref outerKeyRef, 32);
                }
            }
            else
#endif
            {
                int i = 0;
                while (i < key.Length)
                {
                    keys[i] = (byte)(key[i] ^ 0x36);
                    keys[i + blockSize] = (byte)(key[i] ^ 0x5c);
                    i++;
                }

                while (i < blockSize)
                {
                    keys[i] ^= 0x36;
                    keys[i + blockSize] ^= 0x5c;
                    i++;
                }
            }
        }
    }
}
