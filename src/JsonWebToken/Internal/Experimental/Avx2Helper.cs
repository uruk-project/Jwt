#define AVX_PERMUTE
//-----------------------------------------------------------------------------
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace gfoidl.Base64.Internal
{
    internal static class Avx2Helper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Write(Vector256<sbyte> vec, ref char dest)
        {
            // https://github.com/dotnet/coreclr/issues/21130
            Vector256<sbyte> zero = Avx.SetZeroVector256<sbyte>();

            Vector256<sbyte> c0 = Avx2.UnpackLow(vec, zero);
            Vector256<sbyte> c1 = Avx2.UnpackHigh(vec, zero);

#if AVX_PERMUTE
            // Variant with permute is ~10% faster than the other variant
            Vector256<sbyte> t0 = Avx2.Permute2x128(c0, c1, 0x20);
            Vector256<sbyte> t1 = Avx2.Permute2x128(c0, c1, 0x31);

            Unsafe.As<char, Vector256<sbyte>>(ref Unsafe.Add(ref dest,  0)) = t0;
            Unsafe.As<char, Vector256<sbyte>>(ref Unsafe.Add(ref dest, 16)) = t1;
#else
            // https://github.com/dotnet/coreclr/issues/21130
            // Same issue for c0.GetLower(); c0.GetUpper();
            Vector128<sbyte> t0 = Avx.GetLowerHalf(c0);
            Vector128<sbyte> t1 = Avx.GetLowerHalf(c1);
            Vector128<sbyte> t2 = Avx2.ExtractVector128(c0, 1);
            Vector128<sbyte> t3 = Avx2.ExtractVector128(c1, 1);

            Unsafe.As<char, Vector128<sbyte>>(ref Unsafe.Add(ref dest, 0))  = t0;
            Unsafe.As<char, Vector128<sbyte>>(ref Unsafe.Add(ref dest, 8))  = t1;
            Unsafe.As<char, Vector128<sbyte>>(ref Unsafe.Add(ref dest, 16)) = t2;
            Unsafe.As<char, Vector128<sbyte>>(ref Unsafe.Add(ref dest, 24)) = t3;
#endif
        }
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<sbyte> Read(ref char src)
        {
            Vector256<short> c0 = Unsafe.As<char, Vector256<short>>(ref Unsafe.Add(ref src,  0));
            Vector256<short> c1 = Unsafe.As<char, Vector256<short>>(ref Unsafe.Add(ref src, 16));

            Vector256<byte> t0 = Avx2.PackUnsignedSaturate(c0, c1);
            Vector256<long> t1 = Avx2.Permute4x64(Avx.StaticCast<byte, long>(t0), 0b_11_01_10_00);

            return Avx.StaticCast<long, sbyte>(t1);
        }
        //---------------------------------------------------------------------
        public static Vector256<sbyte> LessThan(Vector256<sbyte> left, Vector256<sbyte> right)
        {
            Vector256<sbyte> allOnes = Avx.SetAllVector256<sbyte>(-1);
            return LessThan(left, right, allOnes);
        }
        //---------------------------------------------------------------------
        // There is no intrinsics for that
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Vector256<sbyte> LessThan(Vector256<sbyte> left, Vector256<sbyte> right, Vector256<sbyte> allOnes)
        {
            // (a < b) = ~(a > b) & ~(a = b) = ~((a > b) | (a = b))

            Vector256<sbyte> eq  = Avx2.CompareEqual(left, right);
            Vector256<sbyte> gt  = Avx2.CompareGreaterThan(left, right);
            Vector256<sbyte> or  = Avx2.Or(eq, gt);

            // -1 = 0xFF = true in simd
            return Avx2.AndNot(or, allOnes);
        }
    }
}
