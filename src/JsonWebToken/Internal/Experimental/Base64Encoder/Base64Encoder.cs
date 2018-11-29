#if NETCOREAPP
using System.Runtime.Intrinsics.X86;
#endif

namespace gfoidl.Base64.Internal
{
    public sealed partial class Base64Encoder : Base64EncoderImpl
    {
        static Base64Encoder()
        {
#if NETCOREAPP
#if NETCOREAPP3_0
            if (Ssse3.IsSupported)
#else
            if (Sse2.IsSupported && Ssse3.IsSupported)
#endif
            {
                s_sse_encodeLut = Sse2.SetVector128(
                     0,  0, -16, -19,
                    -4, -4,  -4,  -4,
                    -4, -4,  -4,  -4,
                    -4, -4,  71,  65
                );

                s_sse_decodeLutLo = Sse2.SetVector128(
                    0x1A, 0x1B, 0x1B, 0x1B,
                    0x1A, 0x13, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x15
                );

                s_sse_decodeLutHi = Sse2.SetVector128(
                    0x10, 0x10, 0x10, 0x10,
                    0x10, 0x10, 0x10, 0x10,
                    0x08, 0x04, 0x08, 0x04,
                    0x02, 0x01, 0x10, 0x10
                );

                s_sse_decodeLutShift = Sse2.SetVector128(
                      0,   0,   0,   0,
                      0,   0,   0,   0,
                    -71, -71, -65, -65,
                      4,  19,  16,   0
                );

                s_sse_decodeMask2F = Sse2.SetAllVector128((sbyte)0x2F); // ASCII: /
            }

#if NETCOREAPP3_0
            if (Avx2.IsSupported)
            {
                s_avx_encodeLut = Avx.SetVector256(
                     0,  0, -16, -19,
                    -4, -4,  -4,  -4,
                    -4, -4,  -4,  -4,
                    -4, -4,  71,  65,
                     0,  0, -16, -19,
                    -4, -4,  -4,  -4,
                    -4, -4,  -4,  -4,
                    -4, -4,  71, 65
                );

                s_avx_decodeLutLo = Avx.SetVector256(
                    0x1A, 0x1B, 0x1B, 0x1B,
                    0x1A, 0x13, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x15,
                    0x1A, 0x1B, 0x1B, 0x1B,
                    0x1A, 0x13, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x15
                );

                s_avx_decodeLutHi = Avx.SetVector256(
                    0x10, 0x10, 0x10, 0x10,
                    0x10, 0x10, 0x10, 0x10,
                    0x08, 0x04, 0x08, 0x04,
                    0x02, 0x01, 0x10, 0x10,
                    0x10, 0x10, 0x10, 0x10,
                    0x10, 0x10, 0x10, 0x10,
                    0x08, 0x04, 0x08, 0x04,
                    0x02, 0x01, 0x10, 0x10
                );

                s_avx_decodeLutShift = Avx.SetVector256(
                      0,   0,   0,   0,
                      0,   0,   0,   0,
                    -71, -71, -65, -65,
                      4,  19,  16,   0,
                      0,   0,   0,   0,
                      0,   0,   0,   0,
                    -71, -71, -65, -65,
                      4,  19,  16,   0
                );

                s_avx_decodeMask2F = Avx.SetAllVector256((sbyte)0x2F);     // ASCII: /
            }
#endif
#endif
        }
        //---------------------------------------------------------------------
        private const byte EncodingPad = (byte)'=';     // '=', for padding
    }
}
