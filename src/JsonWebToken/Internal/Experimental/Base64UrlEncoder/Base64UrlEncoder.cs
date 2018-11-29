#if NETCOREAPP
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace gfoidl.Base64.Internal
{
    public sealed partial class Base64UrlEncoder : Base64EncoderImpl
    {
        static Base64UrlEncoder()
        {
#if NETCOREAPP
#if NETCOREAPP3_0
            if (Ssse3.IsSupported)
#else
            if (Sse2.IsSupported && Ssse3.IsSupported)
#endif
            {
                s_sse_encodeLut = Sse2.SetVector128(
                     0,  0, 32, -17,
                    -4, -4, -4,  -4,
                    -4, -4, -4,  -4,
                    -4, -4, 71,  65
                );

                unchecked
                {
                    const sbyte lInv  = (sbyte)0xFF;
                    s_sse_decodeLutLo = Sse2.SetVector128(
                        lInv, lInv, 0x2D, 0x30,
                        0x41, 0x50, 0x61, 0x70,
                        lInv, lInv, lInv, lInv,
                        lInv, lInv, lInv, lInv
                    );
                }

                const sbyte hInv  = 0x00;
                s_sse_decodeLutHi = Sse2.SetVector128(
                    hInv, hInv, 0x2D, 0x39,
                    0x4F, 0x5A, 0x6F, 0x7A,
                    hInv, hInv, hInv, hInv,
                    hInv, hInv, hInv, hInv
                );

                s_sse_decodeLutShift = Sse2.SetVector128(
                      0,   0,  17,   4,
                    -65, -65, -71, -71,
                      0,   0,   0,   0,
                      0,   0,   0,   0
                );

                s_sse_decodeLutLo    = Reverse(s_sse_decodeLutLo);
                s_sse_decodeLutHi    = Reverse(s_sse_decodeLutHi);
                s_sse_decodeLutShift = Reverse(s_sse_decodeLutShift);

                s_sse_decodeMask5F = Sse2.SetAllVector128((sbyte)0x5F); // ASCII: _
            }

#if NETCOREAPP3_0
            if (Avx2.IsSupported)
            {
                s_avx_encodeLut = Avx.SetVector256(
                     0,  0,  32, -17,
                    -4, -4,  -4,  -4,
                    -4, -4,  -4,  -4,
                    -4, -4,  71,  65,
                     0,  0,  32, -17,
                    -4, -4,  -4,  -4,
                    -4, -4,  -4,  -4,
                    -4, -4,  71, 65
                );

                unchecked
                {
                    const sbyte lInv = (sbyte)0xFF;
                    s_avx_decodeLutLo = Avx.SetVector256(
                        lInv, lInv, 0x2D, 0x30,
                        0x41, 0x50, 0x61, 0x70,
                        lInv, lInv, lInv, lInv,
                        lInv, lInv, lInv, lInv,
                        lInv, lInv, 0x2D, 0x30,
                        0x41, 0x50, 0x61, 0x70,
                        lInv, lInv, lInv, lInv,
                        lInv, lInv, lInv, lInv
                    );
                }

                const sbyte hInv = 0x00;
                s_avx_decodeLutHi = Avx.SetVector256(
                    hInv, hInv, 0x2D, 0x39,
                    0x4F, 0x5A, 0x6F, 0x7A,
                    hInv, hInv, hInv, hInv,
                    hInv, hInv, hInv, hInv,
                    hInv, hInv, 0x2D, 0x39,
                    0x4F, 0x5A, 0x6F, 0x7A,
                    hInv, hInv, hInv, hInv,
                    hInv, hInv, hInv, hInv
                );

                s_avx_decodeLutShift = Avx.SetVector256(
                      0,   0,  17,   4,
                    -65, -65, -71, -71,
                      0,   0,   0,   0,
                      0,   0,   0,   0,
                      0,   0,  17,   4,
                    -65, -65, -71, -71,
                      0,   0,   0,   0,
                      0,   0,   0,   0
                );

                s_avx_decodeLutLo    = Reverse(s_avx_decodeLutLo);
                s_avx_decodeLutHi    = Reverse(s_avx_decodeLutHi);
                s_avx_decodeLutShift = Reverse(s_avx_decodeLutShift);

                s_avx_decodeMask5F = Avx.SetAllVector256((sbyte)0x5F);     // ASCII: _
            }
#endif
#endif
        }
        //---------------------------------------------------------------------
#if NETCOREAPP
        private static Vector128<sbyte> Reverse(Vector128<sbyte> vec)
        {
            Vector128<sbyte> mask = Sse2.SetVector128(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            return Ssse3.Shuffle(vec, mask);
        }
#endif
        //---------------------------------------------------------------------
#if NETCOREAPP3_0
        private static Vector256<sbyte> Reverse(Vector256<sbyte> vec)
        {
            Vector256<sbyte> mask = Avx.SetVector256(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
            return Avx2.Shuffle(vec, mask);
        }
#endif
    }
}
