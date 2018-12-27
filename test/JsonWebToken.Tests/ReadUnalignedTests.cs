//using System;
//using System.Numerics;
//using System.Runtime.CompilerServices;
//using System.Runtime.InteropServices;
//using Xunit;

//namespace JsonWebToken.Tests
//{
//    public class ReadUnalignedTests
//    {
//        [Theory]
//        [InlineData(4)]
//        [InlineData(8)]
//        [InlineData(1)]
//        public unsafe void Read_Managed(int size)
//        {
//            Span<byte> data = new byte[size];
//            for (int i = 0; i < size; i++)
//            {
//                data[i] = 255;
//            }

//            ref var array = ref MemoryMarshal.GetReference(data);
//            var value = Unsafe.ReadUnaligned<uint>(ref array);
//        }
//        [Theory]
//        [InlineData(4)]
//        [InlineData(8)]
//        [InlineData(1)]
//        public unsafe void Read_Stackalloc(int size)
//        {
//            Span<byte> data = stackalloc byte[size];
//            for (int i = 0; i < size; i++)
//            {
//                data[i] = 255;
//            }

//            ref var array = ref MemoryMarshal.GetReference(data);
//            var value = Unsafe.ReadUnaligned<uint>(ref array);
//        }

//        [Theory]
//        [InlineData(9)]
//        [InlineData(5)]
//        [InlineData(1)]
//        public unsafe void Read_Unmanaged(int size)
//        {
//            var ptr = Marshal.AllocHGlobal(size);
//            try
//            {
//                Span<byte> data = new Span<byte>(ptr.ToPointer(), size);
//                var equalsTo = new byte[size];
//                for (int i = 0; i < size; i++)
//                {
//                    data[i] = 255;
//                    equalsTo[i] = 255;
//                }

//                ref var array1 = ref MemoryMarshal.GetReference(data);
//                ref var array2 = ref MemoryMarshal.GetReference(equalsTo.AsSpan());
//                //var value = Unsafe.ReadUnaligned<uint>(ref array);

//                Assert.True(SequenceEqual(ref array1, ref array2, (uint)size));
//                Assert.True(SequenceEqual(ref array2, ref array1, (uint)size));
//            }
//            finally
//            {
//                Marshal.FreeHGlobal(ptr);
//            }
//        }

//        // Optimized byte-based SequenceEquals. The "length" parameter for this one is declared a nuint rather than int as we also use it for types other than byte
//        // where the length can exceed 2Gb once scaled by sizeof(T).
//        public static unsafe bool SequenceEqual(ref byte first, ref byte second, uint length)
//        {
//            if (Unsafe.AreSame(ref first, ref second))
//                goto Equal;

//            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
//            IntPtr n = (IntPtr)(void*)length;

//            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
//            {
//                n -= Vector<byte>.Count;
//                while ((byte*)n > (byte*)i)
//                {
//                    if (Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) !=
//                        Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i)))
//                    {
//                        goto NotEqual;
//                    }
//                    i += Vector<byte>.Count;
//                }
//                return Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ==
//                       Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
//            }

//            if ((byte*)n >= (byte*)sizeof(long))
//            {
//                n -= sizeof(long);
//                while ((byte*)n > (byte*)i)
//                {
//                    if (Unsafe.ReadUnaligned<long>(ref Unsafe.AddByteOffset(ref first, i)) !=
//                        Unsafe.ReadUnaligned<long>(ref Unsafe.AddByteOffset(ref second, i)))
//                    {
//                        goto NotEqual;
//                    }
//                    i += sizeof(long);
//                }
//                return Unsafe.ReadUnaligned<long>(ref Unsafe.AddByteOffset(ref first, n)) ==
//                       Unsafe.ReadUnaligned<long>(ref Unsafe.AddByteOffset(ref second, n));
//            }

//            while ((byte*)n > (byte*)i)
//            {
//                if (Unsafe.AddByteOffset(ref first, i) != Unsafe.AddByteOffset(ref second, i))
//                    goto NotEqual;
//                i += 1;
//            }

//            Equal:
//            return true;

//            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
//            return false;
//        }
//    }
//}
