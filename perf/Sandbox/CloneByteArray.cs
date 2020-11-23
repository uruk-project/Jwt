using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [MarkdownExporter]
    public class CloneByteArray
    {
        [Params(8, 16, 32, 1024)]
        public int Size;

        private byte[] data = Array.Empty<byte>();

        [GlobalSetup]
        public void Setup()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                data = new byte[Size];
                rnd.GetBytes(data);
            }
        }

        [Benchmark(Baseline = true)]
        public byte[] Clone()
        {
            return (byte[])data.Clone();
        }

        [Benchmark]
        public byte[] ArrayCopyTo()
        {
            var clone = new byte[data.Length];
            data.CopyTo(clone, 0);
            return clone;
        }

        [Benchmark]
        public byte[] BufferBlockCopy()
        {
            var clone = new byte[data.Length];
            Buffer.BlockCopy(data, 0, clone, 0, data.Length);
            return clone;
        }

        [Benchmark]
        public byte[] SpanCopyTo()
        {
            var clone = new byte[data.Length];
            new ReadOnlySpan<byte>(data, 0, data.Length).CopyTo(clone);
            return clone;
        }

        [Benchmark]
        public byte[] VectorizedCopy()
        {
            var clone = new byte[data.Length];
            VectorizedCopy(data, 0, clone, 0, data.Length);
            return clone;
        }

        [Benchmark]
        public byte[] UnsafeCopyBlockUnaligned()
        {
            var clone = new byte[data.Length];
            Unsafe.CopyBlockUnaligned(ref clone[0], ref data[0], (uint)data.Length);
            return clone;
        }

        [Benchmark]
        public unsafe byte[] UnsafeCopyBlockUnalignedFixed()
        {
            var clone = new byte[data.Length];
            fixed (byte* src = clone)
            fixed (byte* dst = data)
                Unsafe.CopyBlockUnaligned(dst, src, (uint)data.Length);
            return clone;
        }

        [Benchmark]
        public unsafe byte[] UnsafeCopyBlock()
        {
            var clone = new byte[data.Length];
            Unsafe.CopyBlock(ref clone[0], ref data[0], (uint)data.Length);
            return clone;
        }

        [Benchmark]
        public unsafe byte[] UnsafeCopyBlockFixed()
        {
            var clone = new byte[data.Length];
            fixed (byte* src = clone)
            fixed (byte* dst = data)
                Unsafe.CopyBlock(dst, src, (uint)data.Length);
            return clone;
        }

        public static unsafe void VectorizedCopy(byte[] src, int srcOffset, byte[] dst, int dstOffset, int count)
        {
            if (count > 512 + 64)
            {
                // In-built copy faster for large arrays (vs repeated bounds checks on Vector.ctor?)
                Array.Copy(src, srcOffset, dst, dstOffset, count);
                return;
            }
            var orgCount = count;

            while (count >= Vector<byte>.Count)
            {
                new Vector<byte>(src, srcOffset).CopyTo(dst, dstOffset);
                count -= Vector<byte>.Count;
                srcOffset += Vector<byte>.Count;
                dstOffset += Vector<byte>.Count;
            }
            if (orgCount > Vector<byte>.Count)
            {
                new Vector<byte>(src, orgCount - Vector<byte>.Count).CopyTo(dst, orgCount - Vector<byte>.Count);
                return;
            }
            if (src == null || dst == null) throw new ArgumentNullException(nameof(src));
            if (count < 0 || srcOffset < 0 || dstOffset < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (srcOffset + count > src.Length) throw new ArgumentException(nameof(src));
            if (dstOffset + count > dst.Length) throw new ArgumentException(nameof(dst));
            fixed (byte* srcOrigin = src)
            fixed (byte* dstOrigin = dst)
            {
                var pSrc = srcOrigin + srcOffset;
                var pDst = dstOrigin + dstOffset;
                switch (count)
                {
                    case 1:
                        pDst[0] = pSrc[0];
                        return;

                    case 2:
                        *((short*)pDst) = *((short*)pSrc);
                        return;

                    case 3:
                        *((short*)pDst) = *((short*)pSrc);
                        pDst[2] = pSrc[2];
                        return;

                    case 4:
                        *((int*)pDst) = *((int*)pSrc);
                        return;

                    case 5:
                        *((int*)pDst) = *((int*)pSrc);
                        pDst[4] = pSrc[4];
                        return;

                    case 6:
                        *((int*)pDst) = *((int*)pSrc);
                        *((short*)(pDst + 4)) = *((short*)(pSrc + 4));
                        return;

                    case 7:
                        *((int*)pDst) = *((int*)pSrc);
                        *((short*)(pDst + 4)) = *((short*)(pSrc + 4));
                        pDst[6] = pSrc[6];
                        return;

                    case 8:
                        *((long*)pDst) = *((long*)pSrc);
                        return;

                    case 9:
                        *((long*)pDst) = *((long*)pSrc);
                        pDst[8] = pSrc[8];
                        return;

                    case 10:
                        *((long*)pDst) = *((long*)pSrc);
                        *((short*)(pDst + 8)) = *((short*)(pSrc + 8));
                        return;

                    case 11:
                        *((long*)pDst) = *((long*)pSrc);
                        *((short*)(pDst + 8)) = *((short*)(pSrc + 8));
                        pDst[10] = pSrc[10];
                        return;

                    case 12:
                        *((long*)pDst) = *((long*)pSrc);
                        *((int*)(pDst + 8)) = *((int*)(pSrc + 8));
                        return;

                    case 13:
                        *((long*)pDst) = *((long*)pSrc);
                        *((int*)(pDst + 8)) = *((int*)(pSrc + 8));
                        pDst[12] = pSrc[12];
                        return;

                    case 14:
                        *((long*)pDst) = *((long*)pSrc);
                        *((int*)(pDst + 8)) = *((int*)(pSrc + 8));
                        *((short*)(pDst + 12)) = *((short*)(pSrc + 12));
                        return;

                    case 15:
                        *((long*)pDst) = *((long*)pSrc);
                        *((int*)(pDst + 8)) = *((int*)(pSrc + 8));
                        *((short*)(pDst + 12)) = *((short*)(pSrc + 12));
                        pDst[14] = pSrc[14];
                        return;
                }
            }
        }
    }
}
