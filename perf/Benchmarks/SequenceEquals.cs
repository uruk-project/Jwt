using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken.Performance
{
    //[MemoryDiagnoser]
    //public class JsonParserBenchmark
    //{

    //    [Benchmark(Baseline = true)]
    //    [ArgumentsSource(nameof(GetData))]
    //    public unsafe void Specialized(byte[] first, byte[] second)
    //    {
    //        AreEqual_Current(ref MemoryMarshal.GetReference(first.AsSpan()), ref MemoryMarshal.GetReference(second.AsSpan()), first.Length);
    //    }
    //}

    [MemoryDiagnoser]
    public class SequanceEquals
    {

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public unsafe void Equals_Current(byte[] first, byte[] second)
        {
            AreEqual_Current(ref MemoryMarshal.GetReference(first.AsSpan()), ref MemoryMarshal.GetReference(second.AsSpan()), first.Length);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public void Equals_Equals(byte[] first, byte[] second)
        {
            AreEqual_Equals(ref MemoryMarshal.GetReference(first.AsSpan()), ref MemoryMarshal.GetReference(second.AsSpan()), first.Length);
        }


        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public void Equals_Minus(byte[] first, byte[] second)
        {
            AreEqual_Minus(ref MemoryMarshal.GetReference(first.AsSpan()), ref MemoryMarshal.GetReference(second.AsSpan()), first.Length);
        }

#if !NETCOREAPP2_0
        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public void Equals_FixedTime(byte[] first, byte[] second)
        {
            CryptographicOperations.FixedTimeEquals(first, second);
        }
#endif

        public static IEnumerable<object[]> GetData()
        {
            yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "0000000000000000000000000000000000000000000000000000000000000000");
            //yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "0000000000000000000000000000000000000000000000000000000000000001");
            //yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "8000000000000000000000000000000000000000000000000000000000000000");
            //yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "0102040810204080112244880000000000000000000000000000000000000000");
            //yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            //yield return PrepareData("741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336", "741202531e19d673ad7fff334594549e7c81a285dd02865ddd12530612a96336");
        }

        private static object[] PrepareData(string baseValueHex, string errorVectorHex)
        {
            byte[] a = HexToByteArray(baseValueHex);
            byte[] b = HexToByteArray(errorVectorHex);

            for (int i = 0; i < a.Length; i++)
            {
                b[i] ^= a[i];
            }

            return new object[] { a, b };
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Current(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                bool equals = true;
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) ^ Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Equals(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            bool equals = true;
            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals &= (Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i)));
                    i += Vector<byte>.Count;
                }

                return equals & Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
            }

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            while ((byte*)n > (byte*)i)
            {
                equals &= Unsafe.AddByteOffset(ref first, i) == Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return equals;
        }


        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Minus(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) - Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) - Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                bool equals = true;
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) - Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        internal static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

    }
}
