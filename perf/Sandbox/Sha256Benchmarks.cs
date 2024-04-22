using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Performance
{
    public class Sha256Benchmarks
    {
        private static readonly SHA256 _clrSha256 = SHA256.Create();
        private static readonly Sha256_Original _sha256_Original = new Sha256_Original();
        private static readonly Sha256_Original_IntPtr _sha256_Original_IntPtr = new Sha256_Original_IntPtr();
        private static readonly Sha256_Original_IntPtr_KROS _sha256_Original_IntPtr_KROS = new Sha256_Original_IntPtr_KROS();
        private static readonly Sha256_Original_IntPtr_MaskROS _sha256_Original_IntPtr_MaskROS = new Sha256_Original_IntPtr_MaskROS();
        private static readonly Sha256 _sha256 = new Sha256();
        private readonly byte[] _buffer = new byte[32];

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Clr(byte[] value)
        {
            return _clrSha256.ComputeHash(value);
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Optimized(byte[] value)
        {
            _sha256.ComputeHash(value, _buffer);
            return _buffer;
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Original(byte[] value)
        {
            _sha256_Original.ComputeHash(value, _buffer, default, default);
            return _buffer;
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Original_IntPtr(byte[] value)
        {
            _sha256_Original_IntPtr.ComputeHash(value, _buffer, default, default);
            return _buffer;
        }


        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Original_IntPtr_KROS(byte[] value)
        {
            _sha256_Original_IntPtr_KROS.ComputeHash(value, _buffer, default, default);
            return _buffer;
        }


        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Original_IntPtr_MaskROS(byte[] value)
        {
            _sha256_Original_IntPtr_MaskROS.ComputeHash(value, _buffer, default, default);
            return _buffer;
        }

        //private static readonly uint[] W = new uint[64];

        //[Benchmark(Baseline = false)]
        //[ArgumentsSource(nameof(GetData))]
        //public byte[] Sha256_Optimized_SharedBuffer(byte[] value)
        //{
        //    _sha256.ComputeHash(value, _buffer, default, W);
        //    return _buffer;
        //}

        public static IEnumerable<byte[]> GetData()
        {
            //yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 3).ToArray());
            yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048).ToArray());
            //yield return Encoding.UTF8.GetBytes(Enumerable.Repeat('a', 2048 * 16).ToArray());
        }
    }

    public sealed class Sha256_Original : Sha2
    {
        private const int Sha256HashSize = 32;
        private const int Sha256BlockSize = 64;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha256"/> class.
        /// </summary>
        public static readonly Sha256 Shared = new Sha256();

        /// <inheritsdoc />
        public override int HashSize => Sha256HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha256BlockSize;

        /// <inheritsdoc />
        public override int GetWorkingSetSize(int sourceLength)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                return sourceLength >= 4 * Sha256BlockSize ? 64 * 16 : 64 * 4;
            }
            else
#endif
            {
                return 64 * 4;
            }
        }

        /// <inheritsdoc />
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> w)
        {
            if (destination.Length < Sha256HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha256HashSize);
            }

            // init
            Span<uint> state = stackalloc uint[] {
                0x6a09e667u,
                0xbb67ae85u,
                0x3c6ef372u,
                0xa54ff53au,
                0x510e527fu,
                0x9b05688cu,
                0x1f83d9abu,
                0x5be0cd19u
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha256BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha256BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<byte> wTemp = w.Length < 64 * sizeof(uint) ? stackalloc byte[64 * sizeof(uint)] : w;
            ref uint wRef = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(wTemp));
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha256BlockSize)
                {
                    Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha256BlockSize)
                {
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha256BlockSize - prepend.Length;
                    if (dataLength >= Sha256BlockSize)
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.Add(ref srcRef, srcRemained);
                    }
                    else
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, prepend.Length), ref srcRef, (uint)source.Length);
                        goto Final;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha256BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.Add(ref srcStartRef, source.Length - Sha256BlockSize + 1);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                ref byte src128EndRef = ref Unsafe.Add(ref srcStartRef, source.Length - 4 * Sha256BlockSize + 1);
                if (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef))
                {
                    Vector128<uint>[] returnToPool;
                    Span<Vector128<uint>> w4 = returnToPool = ArrayPool<Vector128<uint>>.Shared.Rent(64);
                    try
                    {
                        ref Vector128<uint> w4Ref = ref MemoryMarshal.GetReference(w4);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef));
                    }
                    finally
                    {
                        ArrayPool<Vector128<uint>>.Shared.Return(returnToPool);
                    }
                }
            }
#endif
            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);
        Final:
            // Pad the last block
            Unsafe.Add(ref lastBlockRef, remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha256BlockSize - sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha256BlockSize - sizeof(ulong)).Clear();
            }

            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha256BlockSize - sizeof(ulong)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetReference(state))), _shuffleMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<uint, byte>(ref stateRef)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<uint, byte>(ref stateRef), 16)), _shuffleMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 4), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 1)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 2)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 12), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 3)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 4)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 20), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 5)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 6)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 28), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 7)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Gather(ref byte message)
        {
            var temp = Sse2.ConvertScalarToVector128UInt32(Unsafe.ReadUnaligned<uint>(ref message));
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 16 * 4)), 1);
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 32 * 4)), 2);
            return Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 48 * 4)), 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma0(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 7), Sse2.ShiftRightLogical(W, 18)), Sse2.Xor(Sse2.ShiftRightLogical(W, 3), Sse2.ShiftLeftLogical(W, 25))), Sse2.ShiftLeftLogical(W, 14));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma1(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 17), Sse2.ShiftRightLogical(W, 10)), Sse2.Xor(Sse2.ShiftRightLogical(W, 19), Sse2.ShiftLeftLogical(W, 15))), Sse2.ShiftLeftLogical(W, 13));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Schedule(in Vector128<uint> w0, in Vector128<uint> w1, in Vector128<uint> w9, in Vector128<uint> w14, int i, ref Vector128<uint> schedule)
        {
            Unsafe.Add(ref schedule, i) = Sse2.Add(w0, K128(i));
            return Sse2.Add(Sse2.Add(w0, w9), Sse2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private void Schedule(ref Vector128<uint> schedule, ref byte message)
        {
            Vector128<uint> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            W0 = Ssse3.Shuffle(Gather(ref message).AsByte(), _littleEndianMask128).AsUInt32();
            W1 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 1)).AsByte(), _littleEndianMask128).AsUInt32();
            W2 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 2)).AsByte(), _littleEndianMask128).AsUInt32();
            W3 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 3)).AsByte(), _littleEndianMask128).AsUInt32();
            W4 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 4)).AsByte(), _littleEndianMask128).AsUInt32();
            W5 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 5)).AsByte(), _littleEndianMask128).AsUInt32();
            W6 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 6)).AsByte(), _littleEndianMask128).AsUInt32();
            W7 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 7)).AsByte(), _littleEndianMask128).AsUInt32();
            W8 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 8)).AsByte(), _littleEndianMask128).AsUInt32();
            W9 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 9)).AsByte(), _littleEndianMask128).AsUInt32();
            W10 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 10)).AsByte(), _littleEndianMask128).AsUInt32();
            W11 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 11)).AsByte(), _littleEndianMask128).AsUInt32();
            W12 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 12)).AsByte(), _littleEndianMask128).AsUInt32();
            W13 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 13)).AsByte(), _littleEndianMask128).AsUInt32();
            W14 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 14)).AsByte(), _littleEndianMask128).AsUInt32();
            W15 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 15)).AsByte(), _littleEndianMask128).AsUInt32();
            int i = 0;
            do
            {
                W0 = Schedule(W0, W1, W9, W14, i++, ref schedule);
                W1 = Schedule(W1, W2, W10, W15, i++, ref schedule);
                W2 = Schedule(W2, W3, W11, W0, i++, ref schedule);
                W3 = Schedule(W3, W4, W12, W1, i++, ref schedule);
                W4 = Schedule(W4, W5, W13, W2, i++, ref schedule);
                W5 = Schedule(W5, W6, W14, W3, i++, ref schedule);
                W6 = Schedule(W6, W7, W15, W4, i++, ref schedule);
                W7 = Schedule(W7, W8, W0, W5, i++, ref schedule);
                W8 = Schedule(W8, W9, W1, W6, i++, ref schedule);
                W9 = Schedule(W9, W10, W2, W7, i++, ref schedule);
                W10 = Schedule(W10, W11, W3, W8, i++, ref schedule);
                W11 = Schedule(W11, W12, W4, W9, i++, ref schedule);
                W12 = Schedule(W12, W13, W5, W10, i++, ref schedule);
                W13 = Schedule(W13, W14, W6, W11, i++, ref schedule);
                W14 = Schedule(W14, W15, W7, W12, i++, ref schedule);
                W15 = Schedule(W15, W0, W8, W13, i++, ref schedule);
            }
            while (i < 32);

            W0 = Schedule(W0, W1, W9, W14, i++, ref schedule);
            Unsafe.Add(ref schedule, 48) = Sse2.Add(W0, K128(48));
            W1 = Schedule(W1, W2, W10, W15, i++, ref schedule);
            Unsafe.Add(ref schedule, 49) = Sse2.Add(W1, K128(49));
            W2 = Schedule(W2, W3, W11, W0, i++, ref schedule);
            Unsafe.Add(ref schedule, 50) = Sse2.Add(W2, K128(50));
            W3 = Schedule(W3, W4, W12, W1, i++, ref schedule);
            Unsafe.Add(ref schedule, 51) = Sse2.Add(W3, K128(51));
            W4 = Schedule(W4, W5, W13, W2, i++, ref schedule);
            Unsafe.Add(ref schedule, 52) = Sse2.Add(W4, K128(52));
            W5 = Schedule(W5, W6, W14, W3, i++, ref schedule);
            Unsafe.Add(ref schedule, 53) = Sse2.Add(W5, K128(53));
            W6 = Schedule(W6, W7, W15, W4, i++, ref schedule);
            Unsafe.Add(ref schedule, 54) = Sse2.Add(W6, K128(54));
            W7 = Schedule(W7, W8, W0, W5, i++, ref schedule);
            Unsafe.Add(ref schedule, 55) = Sse2.Add(W7, K128(55));
            W8 = Schedule(W8, W9, W1, W6, i++, ref schedule);
            Unsafe.Add(ref schedule, 56) = Sse2.Add(W8, K128(56));
            W9 = Schedule(W9, W10, W2, W7, i++, ref schedule);
            Unsafe.Add(ref schedule, 57) = Sse2.Add(W9, K128(57));
            W10 = Schedule(W10, W11, W3, W8, i++, ref schedule);
            Unsafe.Add(ref schedule, 58) = Sse2.Add(W10, K128(58));
            W11 = Schedule(W11, W12, W4, W9, i++, ref schedule);
            Unsafe.Add(ref schedule, 59) = Sse2.Add(W11, K128(59));
            W12 = Schedule(W12, W13, W5, W10, i++, ref schedule);
            Unsafe.Add(ref schedule, 60) = Sse2.Add(W12, K128(60));
            W13 = Schedule(W13, W14, W6, W11, i++, ref schedule);
            Unsafe.Add(ref schedule, 61) = Sse2.Add(W13, K128(61));
            W14 = Schedule(W14, W15, W7, W12, i++, ref schedule);
            Unsafe.Add(ref schedule, 62) = Sse2.Add(W14, K128(62));
            W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
            Unsafe.Add(ref schedule, 63) = Sse2.Add(W15, K128(63));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private void Transform(ref uint state, ref byte currentBlock, ref Vector128<uint> w)
        {
            ref uint wEnd = ref Unsafe.As<Vector128<uint>, uint>(ref Unsafe.Add(ref w, 64));
            uint a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (int j = 0; j < 4; j++)
            {
                a = state;
                b = Unsafe.Add(ref state, 1);
                c = Unsafe.Add(ref state, 2);
                d = Unsafe.Add(ref state, 3);
                e = Unsafe.Add(ref state, 4);
                f = Unsafe.Add(ref state, 5);
                g = Unsafe.Add(ref state, 6);
                h = Unsafe.Add(ref state, 7);
                ref uint w0 = ref Unsafe.Add(ref Unsafe.As<Vector128<uint>, uint>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.Add(ref state, 1) += b;
                Unsafe.Add(ref state, 2) += c;
                Unsafe.Add(ref state, 3) += d;
                Unsafe.Add(ref state, 4) += e;
                Unsafe.Add(ref state, 5) += f;
                Unsafe.Add(ref state, 6) += g;
                Unsafe.Add(ref state, 7) += h;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w)
        {
            h += BigSigma1(e) + Ch(e, f, g) + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }
#endif

        private void Transform(ref uint state, ref byte currentBlock, ref uint w)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            ref byte wRef = ref Unsafe.As<uint, byte>(ref w);
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), LittleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), _littleEndianMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref currentBlock, j)));
                }
            }

            ref uint wEnd = ref Unsafe.Add(ref w, 64);
            ref uint w0 = ref Unsafe.Add(ref w, 16);
            do
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            uint a = state;
            uint b = Unsafe.Add(ref state, 1);
            uint c = Unsafe.Add(ref state, 2);
            uint d = Unsafe.Add(ref state, 3);
            uint e = Unsafe.Add(ref state, 4);
            uint f = Unsafe.Add(ref state, 5);
            uint g = Unsafe.Add(ref state, 6);
            uint h = Unsafe.Add(ref state, 7);
            w0 = ref w;
            ref uint k0 = ref k[0];
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.Add(ref state, 1) += b;
            Unsafe.Add(ref state, 2) += c;
            Unsafe.Add(ref state, 3) += d;
            Unsafe.Add(ref state, 4) += e;
            Unsafe.Add(ref state, 5) += f;
            Unsafe.Add(ref state, 6) += g;
            Unsafe.Add(ref state, 7) += h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w, uint k)
        {
            h += BigSigma1(e) + Ch(e, f, g) + k + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateRight(uint a, byte b)
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            => BitOperations.RotateRight(a, b);
#else
            => (a >> b) | (a << (32 - b));
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma0(uint a)
            => RotateRight(RotateRight(RotateRight(a, 9) ^ a, 11) ^ a, 2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma1(uint e)
              => RotateRight(RotateRight(RotateRight(e, 14) ^ e, 5) ^ e, 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma1(uint x)
            => RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma0(uint x)
            => RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Ch(uint x, uint y, uint z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Maj(uint x, uint y, uint z)
            => ((x | y) & z) | (x & y);

        private static readonly uint[] k = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> LittleEndianMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _littleEndianMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> K128(int i) => Unsafe.Add(ref _k128[0], i);

        private static readonly Vector128<uint>[] _k128 = {
            Vector128.Create(0x428a2f98u),
            Vector128.Create(0x71374491u),
            Vector128.Create(0xb5c0fbcfu),
            Vector128.Create(0xe9b5dba5u),
            Vector128.Create(0x3956c25bu),
            Vector128.Create(0x59f111f1u),
            Vector128.Create(0x923f82a4u),
            Vector128.Create(0xab1c5ed5u),
            Vector128.Create(0xd807aa98u),
            Vector128.Create(0x12835b01u),
            Vector128.Create(0x243185beu),
            Vector128.Create(0x550c7dc3u),
            Vector128.Create(0x72be5d74u),
            Vector128.Create(0x80deb1feu),
            Vector128.Create(0x9bdc06a7u),
            Vector128.Create(0xc19bf174u),
            Vector128.Create(0xe49b69c1u),
            Vector128.Create(0xefbe4786u),
            Vector128.Create(0x0fc19dc6u),
            Vector128.Create(0x240ca1ccu),
            Vector128.Create(0x2de92c6fu),
            Vector128.Create(0x4a7484aau),
            Vector128.Create(0x5cb0a9dcu),
            Vector128.Create(0x76f988dau),
            Vector128.Create(0x983e5152u),
            Vector128.Create(0xa831c66du),
            Vector128.Create(0xb00327c8u),
            Vector128.Create(0xbf597fc7u),
            Vector128.Create(0xc6e00bf3u),
            Vector128.Create(0xd5a79147u),
            Vector128.Create(0x06ca6351u),
            Vector128.Create(0x14292967u),
            Vector128.Create(0x27b70a85u),
            Vector128.Create(0x2e1b2138u),
            Vector128.Create(0x4d2c6dfcu),
            Vector128.Create(0x53380d13u),
            Vector128.Create(0x650a7354u),
            Vector128.Create(0x766a0abbu),
            Vector128.Create(0x81c2c92eu),
            Vector128.Create(0x92722c85u),
            Vector128.Create(0xa2bfe8a1u),
            Vector128.Create(0xa81a664bu),
            Vector128.Create(0xc24b8b70u),
            Vector128.Create(0xc76c51a3u),
            Vector128.Create(0xd192e819u),
            Vector128.Create(0xd6990624u),
            Vector128.Create(0xf40e3585u),
            Vector128.Create(0x106aa070u),
            Vector128.Create(0x19a4c116u),
            Vector128.Create(0x1e376c08u),
            Vector128.Create(0x2748774cu),
            Vector128.Create(0x34b0bcb5u),
            Vector128.Create(0x391c0cb3u),
            Vector128.Create(0x4ed8aa4au),
            Vector128.Create(0x5b9cca4fu),
            Vector128.Create(0x682e6ff3u),
            Vector128.Create(0x748f82eeu),
            Vector128.Create(0x78a5636fu),
            Vector128.Create(0x84c87814u),
            Vector128.Create(0x8cc70208u),
            Vector128.Create(0x90befffau),
            Vector128.Create(0xa4506cebu),
            Vector128.Create(0xbef9a3f7u),
            Vector128.Create(0xc67178f2u)
        };

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> _shuffleMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _shuffleMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

#endif
    }

    public sealed class Sha256_Original_IntPtr : Sha2
    {
        private const int Sha256HashSize = 32;
        private const int Sha256BlockSize = 64;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha256"/> class.
        /// </summary>
        public static readonly Sha256 Shared = new Sha256();

        /// <inheritsdoc />
        public override int HashSize => Sha256HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha256BlockSize;

        /// <inheritsdoc />
        public override int GetWorkingSetSize(int sourceLength)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                return sourceLength >= 4 * Sha256BlockSize ? 64 * 16 : 64 * 4;
            }
            else
#endif
            {
                return 64 * 4;
            }
        }

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> w)
        {
            if (destination.Length < Sha256HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha256HashSize);
            }

            // init
            Span<uint> state = stackalloc uint[] {
                0x6a09e667u,
                0xbb67ae85u,
                0x3c6ef372u,
                0xa54ff53au,
                0x510e527fu,
                0x9b05688cu,
                0x1f83d9abu,
                0x5be0cd19u
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha256BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha256BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<byte> wTemp = w.Length < 64 * sizeof(uint) ? stackalloc byte[64 * sizeof(uint)] : w;
            ref uint wRef = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(wTemp));
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha256BlockSize)
                {
                    Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha256BlockSize)
                {
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha256BlockSize - prepend.Length;
                    if (dataLength >= Sha256BlockSize)
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.Add(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Final;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha256BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.Add(ref srcStartRef, source.Length - Sha256BlockSize + 1);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                ref byte src128EndRef = ref Unsafe.Add(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha256BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef))
                {
                    Vector128<uint>[] returnToPool;
                    Span<Vector128<uint>> w4 = returnToPool = ArrayPool<Vector128<uint>>.Shared.Rent(64);
                    try
                    {
                        ref Vector128<uint> w4Ref = ref MemoryMarshal.GetReference(w4);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef));
                    }
                    finally
                    {
                        ArrayPool<Vector128<uint>>.Shared.Return(returnToPool);
                    }
                }
            }
#endif
            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);
        Final:
            // Pad the last block
            Unsafe.Add(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha256BlockSize - sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha256BlockSize - sizeof(ulong)).Clear();
            }

            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha256BlockSize - sizeof(ulong)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetReference(state))), _shuffleMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<uint, byte>(ref stateRef)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<uint, byte>(ref stateRef), 16)), _shuffleMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 4), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 1)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 2)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 12), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 3)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 4)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 20), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 5)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 6)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 28), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 7)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Gather(ref byte message)
        {
            var temp = Sse2.ConvertScalarToVector128UInt32(Unsafe.ReadUnaligned<uint>(ref message));
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 16 * 4)), 1);
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 32 * 4)), 2);
            return Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 48 * 4)), 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma0(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 7), Sse2.ShiftRightLogical(W, 18)), Sse2.Xor(Sse2.ShiftRightLogical(W, 3), Sse2.ShiftLeftLogical(W, 25))), Sse2.ShiftLeftLogical(W, 14));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma1(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 17), Sse2.ShiftRightLogical(W, 10)), Sse2.Xor(Sse2.ShiftRightLogical(W, 19), Sse2.ShiftLeftLogical(W, 15))), Sse2.ShiftLeftLogical(W, 13));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Schedule(in Vector128<uint> w0, in Vector128<uint> w1, in Vector128<uint> w9, in Vector128<uint> w14, IntPtr i, ref Vector128<uint> schedule)
        {
            Unsafe.Add(ref schedule, i) = Sse2.Add(w0, K128(i));
            return Sse2.Add(Sse2.Add(w0, w9), Sse2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private unsafe void Schedule(ref Vector128<uint> schedule, ref byte message)
        {
            Vector128<uint> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            W0 = Ssse3.Shuffle(Gather(ref message).AsByte(), _littleEndianMask128).AsUInt32();
            W1 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 1)).AsByte(), _littleEndianMask128).AsUInt32();
            W2 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 2)).AsByte(), _littleEndianMask128).AsUInt32();
            W3 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 3)).AsByte(), _littleEndianMask128).AsUInt32();
            W4 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 4)).AsByte(), _littleEndianMask128).AsUInt32();
            W5 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 5)).AsByte(), _littleEndianMask128).AsUInt32();
            W6 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 6)).AsByte(), _littleEndianMask128).AsUInt32();
            W7 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 7)).AsByte(), _littleEndianMask128).AsUInt32();
            W8 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 8)).AsByte(), _littleEndianMask128).AsUInt32();
            W9 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 9)).AsByte(), _littleEndianMask128).AsUInt32();
            W10 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 10)).AsByte(), _littleEndianMask128).AsUInt32();
            W11 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 11)).AsByte(), _littleEndianMask128).AsUInt32();
            W12 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 12)).AsByte(), _littleEndianMask128).AsUInt32();
            W13 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 13)).AsByte(), _littleEndianMask128).AsUInt32();
            W14 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 14)).AsByte(), _littleEndianMask128).AsUInt32();
            W15 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 15)).AsByte(), _littleEndianMask128).AsUInt32();
            IntPtr i = (IntPtr)0;
            do
            {
                W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
                i += 1;
                W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
                i += 1;
                W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
                i += 1;
                W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
                i += 1;
                W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
                i += 1;
                W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
                i += 1;
                W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
                i += 1;
                W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
                i += 1;
                W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
                i += 1;
                W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
                i += 1;
                W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
                i += 1;
                W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
                i += 1;
                W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
                i += 1;
                W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
                i += 1;
                W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
                i += 1;
                W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
                i += 1;
            } while ((byte*)i < (byte*)32);


            W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 48) = Sse2.Add(W0, K128((IntPtr)48));
            W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 49) = Sse2.Add(W1, K128((IntPtr)49));
            W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 50) = Sse2.Add(W2, K128((IntPtr)50));
            W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 51) = Sse2.Add(W3, K128((IntPtr)51));
            W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 52) = Sse2.Add(W4, K128((IntPtr)52));
            W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 53) = Sse2.Add(W5, K128((IntPtr)53));
            W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 54) = Sse2.Add(W6, K128((IntPtr)54));
            W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 55) = Sse2.Add(W7, K128((IntPtr)55));
            W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 56) = Sse2.Add(W8, K128((IntPtr)56));
            W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 57) = Sse2.Add(W9, K128((IntPtr)57));
            W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 58) = Sse2.Add(W10, K128((IntPtr)58));
            W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 59) = Sse2.Add(W11, K128((IntPtr)59));
            W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 60) = Sse2.Add(W12, K128((IntPtr)60));
            W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 61) = Sse2.Add(W13, K128((IntPtr)61));
            W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 62) = Sse2.Add(W14, K128((IntPtr)62));
            W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
            Unsafe.Add(ref schedule, 63) = Sse2.Add(W15, K128((IntPtr)63));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private void Transform(ref uint state, ref byte currentBlock, ref Vector128<uint> w)
        {
            ref uint wEnd = ref Unsafe.As<Vector128<uint>, uint>(ref Unsafe.Add(ref w, 64));
            uint a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (int j = 0; j < 4; j++)
            {
                a = state;
                b = Unsafe.Add(ref state, 1);
                c = Unsafe.Add(ref state, 2);
                d = Unsafe.Add(ref state, 3);
                e = Unsafe.Add(ref state, 4);
                f = Unsafe.Add(ref state, 5);
                g = Unsafe.Add(ref state, 6);
                h = Unsafe.Add(ref state, 7);
                ref uint w0 = ref Unsafe.Add(ref Unsafe.As<Vector128<uint>, uint>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.Add(ref state, 1) += b;
                Unsafe.Add(ref state, 2) += c;
                Unsafe.Add(ref state, 3) += d;
                Unsafe.Add(ref state, 4) += e;
                Unsafe.Add(ref state, 5) += f;
                Unsafe.Add(ref state, 6) += g;
                Unsafe.Add(ref state, 7) += h;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w)
        {
            h += BigSigma1(e) + Ch(e, f, g) + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }
#endif

        private void Transform(ref uint state, ref byte currentBlock, ref uint w)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            ref byte wRef = ref Unsafe.As<uint, byte>(ref w);
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), LittleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), _littleEndianMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref currentBlock, j)));
                }
            }

            ref uint wEnd = ref Unsafe.Add(ref w, 64);
            ref uint w0 = ref Unsafe.Add(ref w, 16);
            do
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            uint a = state;
            uint b = Unsafe.Add(ref state, 1);
            uint c = Unsafe.Add(ref state, 2);
            uint d = Unsafe.Add(ref state, 3);
            uint e = Unsafe.Add(ref state, 4);
            uint f = Unsafe.Add(ref state, 5);
            uint g = Unsafe.Add(ref state, 6);
            uint h = Unsafe.Add(ref state, 7);
            w0 = ref w;
            ref uint k0 = ref k[0];
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.Add(ref state, 1) += b;
            Unsafe.Add(ref state, 2) += c;
            Unsafe.Add(ref state, 3) += d;
            Unsafe.Add(ref state, 4) += e;
            Unsafe.Add(ref state, 5) += f;
            Unsafe.Add(ref state, 6) += g;
            Unsafe.Add(ref state, 7) += h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w, uint k)
        {
            h += BigSigma1(e) + Ch(e, f, g) + k + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateRight(uint a, byte b)
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            => BitOperations.RotateRight(a, b);
#else
            => (a >> b) | (a << (32 - b));
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma0(uint a)
            => RotateRight(RotateRight(RotateRight(a, 9) ^ a, 11) ^ a, 2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma1(uint e)
              => RotateRight(RotateRight(RotateRight(e, 14) ^ e, 5) ^ e, 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma1(uint x)
            => RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma0(uint x)
            => RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Ch(uint x, uint y, uint z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Maj(uint x, uint y, uint z)
            => ((x | y) & z) | (x & y);

        private static readonly uint[] k = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> LittleEndianMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _littleEndianMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> K128(IntPtr i) => Unsafe.Add(ref _k128[0], i);

        private static readonly Vector128<uint>[] _k128 = {
            Vector128.Create(0x428a2f98u),
            Vector128.Create(0x71374491u),
            Vector128.Create(0xb5c0fbcfu),
            Vector128.Create(0xe9b5dba5u),
            Vector128.Create(0x3956c25bu),
            Vector128.Create(0x59f111f1u),
            Vector128.Create(0x923f82a4u),
            Vector128.Create(0xab1c5ed5u),
            Vector128.Create(0xd807aa98u),
            Vector128.Create(0x12835b01u),
            Vector128.Create(0x243185beu),
            Vector128.Create(0x550c7dc3u),
            Vector128.Create(0x72be5d74u),
            Vector128.Create(0x80deb1feu),
            Vector128.Create(0x9bdc06a7u),
            Vector128.Create(0xc19bf174u),
            Vector128.Create(0xe49b69c1u),
            Vector128.Create(0xefbe4786u),
            Vector128.Create(0x0fc19dc6u),
            Vector128.Create(0x240ca1ccu),
            Vector128.Create(0x2de92c6fu),
            Vector128.Create(0x4a7484aau),
            Vector128.Create(0x5cb0a9dcu),
            Vector128.Create(0x76f988dau),
            Vector128.Create(0x983e5152u),
            Vector128.Create(0xa831c66du),
            Vector128.Create(0xb00327c8u),
            Vector128.Create(0xbf597fc7u),
            Vector128.Create(0xc6e00bf3u),
            Vector128.Create(0xd5a79147u),
            Vector128.Create(0x06ca6351u),
            Vector128.Create(0x14292967u),
            Vector128.Create(0x27b70a85u),
            Vector128.Create(0x2e1b2138u),
            Vector128.Create(0x4d2c6dfcu),
            Vector128.Create(0x53380d13u),
            Vector128.Create(0x650a7354u),
            Vector128.Create(0x766a0abbu),
            Vector128.Create(0x81c2c92eu),
            Vector128.Create(0x92722c85u),
            Vector128.Create(0xa2bfe8a1u),
            Vector128.Create(0xa81a664bu),
            Vector128.Create(0xc24b8b70u),
            Vector128.Create(0xc76c51a3u),
            Vector128.Create(0xd192e819u),
            Vector128.Create(0xd6990624u),
            Vector128.Create(0xf40e3585u),
            Vector128.Create(0x106aa070u),
            Vector128.Create(0x19a4c116u),
            Vector128.Create(0x1e376c08u),
            Vector128.Create(0x2748774cu),
            Vector128.Create(0x34b0bcb5u),
            Vector128.Create(0x391c0cb3u),
            Vector128.Create(0x4ed8aa4au),
            Vector128.Create(0x5b9cca4fu),
            Vector128.Create(0x682e6ff3u),
            Vector128.Create(0x748f82eeu),
            Vector128.Create(0x78a5636fu),
            Vector128.Create(0x84c87814u),
            Vector128.Create(0x8cc70208u),
            Vector128.Create(0x90befffau),
            Vector128.Create(0xa4506cebu),
            Vector128.Create(0xbef9a3f7u),
            Vector128.Create(0xc67178f2u)
        };

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> _shuffleMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _shuffleMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

#endif
    }
    public class Sha256_Original_IntPtr_MaskROS : Sha2
    {
        private const int Sha256HashSize = 32;
        private const int Sha256BlockSize = 64;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha256"/> class.
        /// </summary>
        public static readonly Sha256 Shared = new Sha256();

        /// <inheritsdoc />
        public override int HashSize => Sha256HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha256BlockSize;

        /// <inheritsdoc />
        public override int GetWorkingSetSize(int sourceLength)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                return sourceLength >= 4 * Sha256BlockSize ? 64 * 16 : 64 * 4;
            }
            else
#endif
            {
                return 64 * 4;
            }
        }

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> w)
        {
            if (destination.Length < Sha256HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha256HashSize);
            }

            // init
            Span<uint> state = stackalloc uint[] {
                0x6a09e667u,
                0xbb67ae85u,
                0x3c6ef372u,
                0xa54ff53au,
                0x510e527fu,
                0x9b05688cu,
                0x1f83d9abu,
                0x5be0cd19u
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha256BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha256BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<byte> wTemp = w.Length < 64 * sizeof(uint) ? stackalloc byte[64 * sizeof(uint)] : w;
            ref uint wRef = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(wTemp));
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha256BlockSize)
                {
                    Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha256BlockSize)
                {
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha256BlockSize - prepend.Length;
                    if (dataLength >= Sha256BlockSize)
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.Add(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Final;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha256BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.Add(ref srcStartRef, source.Length - Sha256BlockSize + 1);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                ref byte src128EndRef = ref Unsafe.Add(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha256BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef))
                {
                    Vector128<uint>[] returnToPool;
                    Span<Vector128<uint>> w4 = returnToPool = ArrayPool<Vector128<uint>>.Shared.Rent(64);
                    try
                    {
                        ref Vector128<uint> w4Ref = ref MemoryMarshal.GetReference(w4);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef));
                    }
                    finally
                    {
                        ArrayPool<Vector128<uint>>.Shared.Return(returnToPool);
                    }
                }
            }
#endif
            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);
        Final:
            // Pad the last block
            Unsafe.Add(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha256BlockSize - sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha256BlockSize - sizeof(ulong)).Clear();
            }

            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha256BlockSize - sizeof(ulong)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetReference(state))), _shuffleMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<uint, byte>(ref stateRef)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<uint, byte>(ref stateRef), 16)), _shuffleMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 4), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 1)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 2)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 12), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 3)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 4)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 20), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 5)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 6)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 28), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 7)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Gather(ref byte message)
        {
            var temp = Sse2.ConvertScalarToVector128UInt32(Unsafe.ReadUnaligned<uint>(ref message));
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 16 * 4)), 1);
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 32 * 4)), 2);
            return Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 48 * 4)), 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma0(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 7), Sse2.ShiftRightLogical(W, 18)), Sse2.Xor(Sse2.ShiftRightLogical(W, 3), Sse2.ShiftLeftLogical(W, 25))), Sse2.ShiftLeftLogical(W, 14));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma1(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 17), Sse2.ShiftRightLogical(W, 10)), Sse2.Xor(Sse2.ShiftRightLogical(W, 19), Sse2.ShiftLeftLogical(W, 15))), Sse2.ShiftLeftLogical(W, 13));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Schedule(in Vector128<uint> w0, in Vector128<uint> w1, in Vector128<uint> w9, in Vector128<uint> w14, IntPtr i, ref Vector128<uint> schedule)
        {
            Unsafe.Add(ref schedule, i) = Sse2.Add(w0, K128(i));
            return Sse2.Add(Sse2.Add(w0, w9), Sse2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private unsafe void Schedule(ref Vector128<uint> schedule, ref byte message)
        {
            Vector128<uint> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            var _littleEndianMask128 = EndiannessMask128UInt32;
            W0 = Ssse3.Shuffle(Gather(ref message).AsByte(), _littleEndianMask128).AsUInt32();
            W1 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 1)).AsByte(), _littleEndianMask128).AsUInt32();
            W2 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 2)).AsByte(), _littleEndianMask128).AsUInt32();
            W3 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 3)).AsByte(), _littleEndianMask128).AsUInt32();
            W4 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 4)).AsByte(), _littleEndianMask128).AsUInt32();
            W5 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 5)).AsByte(), _littleEndianMask128).AsUInt32();
            W6 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 6)).AsByte(), _littleEndianMask128).AsUInt32();
            W7 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 7)).AsByte(), _littleEndianMask128).AsUInt32();
            W8 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 8)).AsByte(), _littleEndianMask128).AsUInt32();
            W9 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 9)).AsByte(), _littleEndianMask128).AsUInt32();
            W10 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 10)).AsByte(), _littleEndianMask128).AsUInt32();
            W11 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 11)).AsByte(), _littleEndianMask128).AsUInt32();
            W12 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 12)).AsByte(), _littleEndianMask128).AsUInt32();
            W13 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 13)).AsByte(), _littleEndianMask128).AsUInt32();
            W14 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 14)).AsByte(), _littleEndianMask128).AsUInt32();
            W15 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 15)).AsByte(), _littleEndianMask128).AsUInt32();
            IntPtr i = (IntPtr)0;
            do
            {
                W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
                i += 1;
                W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
                i += 1;
                W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
                i += 1;
                W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
                i += 1;
                W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
                i += 1;
                W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
                i += 1;
                W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
                i += 1;
                W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
                i += 1;
                W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
                i += 1;
                W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
                i += 1;
                W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
                i += 1;
                W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
                i += 1;
                W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
                i += 1;
                W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
                i += 1;
                W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
                i += 1;
                W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
                i += 1;
            } while ((byte*)i < (byte*)32);


            W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 48) = Sse2.Add(W0, K128((IntPtr)48));
            W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 49) = Sse2.Add(W1, K128((IntPtr)49));
            W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 50) = Sse2.Add(W2, K128((IntPtr)50));
            W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 51) = Sse2.Add(W3, K128((IntPtr)51));
            W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 52) = Sse2.Add(W4, K128((IntPtr)52));
            W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 53) = Sse2.Add(W5, K128((IntPtr)53));
            W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 54) = Sse2.Add(W6, K128((IntPtr)54));
            W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 55) = Sse2.Add(W7, K128((IntPtr)55));
            W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 56) = Sse2.Add(W8, K128((IntPtr)56));
            W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 57) = Sse2.Add(W9, K128((IntPtr)57));
            W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 58) = Sse2.Add(W10, K128((IntPtr)58));
            W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 59) = Sse2.Add(W11, K128((IntPtr)59));
            W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 60) = Sse2.Add(W12, K128((IntPtr)60));
            W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 61) = Sse2.Add(W13, K128((IntPtr)61));
            W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
            i += 1;
            Unsafe.Add(ref schedule, 62) = Sse2.Add(W14, K128((IntPtr)62));
            W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
            Unsafe.Add(ref schedule, 63) = Sse2.Add(W15, K128((IntPtr)63));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private void Transform(ref uint state, ref byte currentBlock, ref Vector128<uint> w)
        {
            ref uint wEnd = ref Unsafe.As<Vector128<uint>, uint>(ref Unsafe.Add(ref w, 64));
            uint a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (int j = 0; j < 4; j++)
            {
                a = state;
                b = Unsafe.Add(ref state, 1);
                c = Unsafe.Add(ref state, 2);
                d = Unsafe.Add(ref state, 3);
                e = Unsafe.Add(ref state, 4);
                f = Unsafe.Add(ref state, 5);
                g = Unsafe.Add(ref state, 6);
                h = Unsafe.Add(ref state, 7);
                ref uint w0 = ref Unsafe.Add(ref Unsafe.As<Vector128<uint>, uint>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.Add(ref state, 1) += b;
                Unsafe.Add(ref state, 2) += c;
                Unsafe.Add(ref state, 3) += d;
                Unsafe.Add(ref state, 4) += e;
                Unsafe.Add(ref state, 5) += f;
                Unsafe.Add(ref state, 6) += g;
                Unsafe.Add(ref state, 7) += h;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w)
        {
            h += BigSigma1(e) + Ch(e, f, g) + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }
#endif

        private void Transform(ref uint state, ref byte currentBlock, ref uint w)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            ref byte wRef = ref Unsafe.As<uint, byte>(ref w);
            if (Avx2.IsSupported)
            {
                var LittleEndianMask256 = EndianessnMask256UInt32;
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), LittleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                var _littleEndianMask128 = EndiannessMask128UInt32;
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), _littleEndianMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref currentBlock, j)));
                }
            }

            ref uint wEnd = ref Unsafe.Add(ref w, 64);
            ref uint w0 = ref Unsafe.Add(ref w, 16);
            do
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            uint a = state;
            uint b = Unsafe.Add(ref state, 1);
            uint c = Unsafe.Add(ref state, 2);
            uint d = Unsafe.Add(ref state, 3);
            uint e = Unsafe.Add(ref state, 4);
            uint f = Unsafe.Add(ref state, 5);
            uint g = Unsafe.Add(ref state, 6);
            uint h = Unsafe.Add(ref state, 7);
            w0 = ref w;
            ref uint k0 = ref k[0];
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.Add(ref state, 1) += b;
            Unsafe.Add(ref state, 2) += c;
            Unsafe.Add(ref state, 3) += d;
            Unsafe.Add(ref state, 4) += e;
            Unsafe.Add(ref state, 5) += f;
            Unsafe.Add(ref state, 6) += g;
            Unsafe.Add(ref state, 7) += h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w, uint k)
        {
            h += BigSigma1(e) + Ch(e, f, g) + k + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateRight(uint a, byte b)
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            => BitOperations.RotateRight(a, b);
#else
            => (a >> b) | (a << (32 - b));
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma0(uint a)
            => RotateRight(RotateRight(RotateRight(a, 9) ^ a, 11) ^ a, 2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma1(uint e)
              => RotateRight(RotateRight(RotateRight(e, 14) ^ e, 5) ^ e, 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma1(uint x)
            => RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma0(uint x)
            => RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Ch(uint x, uint y, uint z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Maj(uint x, uint y, uint z)
            => ((x | y) & z) | (x & y);

        private static readonly uint[] k = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> K128(IntPtr i) => Unsafe.Add(ref _k128[0], i);

        private static readonly Vector128<uint>[] _k128 = {
            Vector128.Create(0x428a2f98u),
            Vector128.Create(0x71374491u),
            Vector128.Create(0xb5c0fbcfu),
            Vector128.Create(0xe9b5dba5u),
            Vector128.Create(0x3956c25bu),
            Vector128.Create(0x59f111f1u),
            Vector128.Create(0x923f82a4u),
            Vector128.Create(0xab1c5ed5u),
            Vector128.Create(0xd807aa98u),
            Vector128.Create(0x12835b01u),
            Vector128.Create(0x243185beu),
            Vector128.Create(0x550c7dc3u),
            Vector128.Create(0x72be5d74u),
            Vector128.Create(0x80deb1feu),
            Vector128.Create(0x9bdc06a7u),
            Vector128.Create(0xc19bf174u),
            Vector128.Create(0xe49b69c1u),
            Vector128.Create(0xefbe4786u),
            Vector128.Create(0x0fc19dc6u),
            Vector128.Create(0x240ca1ccu),
            Vector128.Create(0x2de92c6fu),
            Vector128.Create(0x4a7484aau),
            Vector128.Create(0x5cb0a9dcu),
            Vector128.Create(0x76f988dau),
            Vector128.Create(0x983e5152u),
            Vector128.Create(0xa831c66du),
            Vector128.Create(0xb00327c8u),
            Vector128.Create(0xbf597fc7u),
            Vector128.Create(0xc6e00bf3u),
            Vector128.Create(0xd5a79147u),
            Vector128.Create(0x06ca6351u),
            Vector128.Create(0x14292967u),
            Vector128.Create(0x27b70a85u),
            Vector128.Create(0x2e1b2138u),
            Vector128.Create(0x4d2c6dfcu),
            Vector128.Create(0x53380d13u),
            Vector128.Create(0x650a7354u),
            Vector128.Create(0x766a0abbu),
            Vector128.Create(0x81c2c92eu),
            Vector128.Create(0x92722c85u),
            Vector128.Create(0xa2bfe8a1u),
            Vector128.Create(0xa81a664bu),
            Vector128.Create(0xc24b8b70u),
            Vector128.Create(0xc76c51a3u),
            Vector128.Create(0xd192e819u),
            Vector128.Create(0xd6990624u),
            Vector128.Create(0xf40e3585u),
            Vector128.Create(0x106aa070u),
            Vector128.Create(0x19a4c116u),
            Vector128.Create(0x1e376c08u),
            Vector128.Create(0x2748774cu),
            Vector128.Create(0x34b0bcb5u),
            Vector128.Create(0x391c0cb3u),
            Vector128.Create(0x4ed8aa4au),
            Vector128.Create(0x5b9cca4fu),
            Vector128.Create(0x682e6ff3u),
            Vector128.Create(0x748f82eeu),
            Vector128.Create(0x78a5636fu),
            Vector128.Create(0x84c87814u),
            Vector128.Create(0x8cc70208u),
            Vector128.Create(0x90befffau),
            Vector128.Create(0xa4506cebu),
            Vector128.Create(0xbef9a3f7u),
            Vector128.Create(0xc67178f2u)
        };

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> _shuffleMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _shuffleMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

#endif
    }

    public class Sha256_Original_IntPtr_KROS : Sha2
    {
        private const int Sha256HashSize = 32;
        private const int Sha256BlockSize = 64;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha256"/> class.
        /// </summary>
        public static readonly Sha256 Shared = new Sha256();

        /// <inheritsdoc />
        public override int HashSize => Sha256HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha256BlockSize;

        /// <inheritsdoc />
        public override int GetWorkingSetSize(int sourceLength)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                return sourceLength >= 4 * Sha256BlockSize ? 64 * 16 : 64 * 4;
            }
            else
#endif
            {
                return 64 * 4;
            }
        }

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> w)
        {
            if (destination.Length < Sha256HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha256HashSize);
            }

            // init
            Span<uint> state = stackalloc uint[] {
                0x6a09e667u,
                0xbb67ae85u,
                0x3c6ef372u,
                0xa54ff53au,
                0x510e527fu,
                0x9b05688cu,
                0x1f83d9abu,
                0x5be0cd19u
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha256BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha256BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<byte> wTemp = w.Length < 64 * sizeof(uint) ? stackalloc byte[64 * sizeof(uint)] : w;
            ref uint wRef = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(wTemp));
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha256BlockSize)
                {
                    Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha256BlockSize)
                {
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha256BlockSize - prepend.Length;
                    if (dataLength >= Sha256BlockSize)
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.Add(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Final;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha256BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.Add(ref srcStartRef, source.Length - Sha256BlockSize + 1);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Ssse3.IsSupported)
            {
                ref byte src128EndRef = ref Unsafe.Add(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha256BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef))
                {
                    Vector128<uint>[] returnToPool;
                    Span<Vector128<uint>> w4 = returnToPool = ArrayPool<Vector128<uint>>.Shared.Rent(64);
                    try
                    {
                        ref Vector128<uint> w4Ref = ref MemoryMarshal.GetReference(w4);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref src128EndRef));
                    }
                    finally
                    {
                        ArrayPool<Vector128<uint>>.Shared.Return(returnToPool);
                    }
                }
            }
#endif
            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.Add(ref srcRef, Sha256BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);
        Final:
            // Pad the last block
            Unsafe.Add(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha256BlockSize - sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha256BlockSize - sizeof(ulong)).Clear();
            }

            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha256BlockSize - sizeof(ulong)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetReference(state))), _shuffleMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<uint, byte>(ref stateRef)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<uint, byte>(ref stateRef), 16)), _shuffleMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 4), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 1)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 2)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 12), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 3)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 4)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 20), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 5)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 6)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 28), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 7)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Gather(ref byte message)
        {
            var temp = Sse2.ConvertScalarToVector128UInt32(Unsafe.ReadUnaligned<uint>(ref message));
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 16 * 4)), 1);
            temp = Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 32 * 4)), 2);
            return Sse41.Insert(temp, Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref message, 48 * 4)), 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma0(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 7), Sse2.ShiftRightLogical(W, 18)), Sse2.Xor(Sse2.ShiftRightLogical(W, 3), Sse2.ShiftLeftLogical(W, 25))), Sse2.ShiftLeftLogical(W, 14));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Sigma1(in Vector128<uint> W)
        {
            return Sse2.Xor(Sse2.Xor(Sse2.Xor(Sse2.ShiftRightLogical(W, 17), Sse2.ShiftRightLogical(W, 10)), Sse2.Xor(Sse2.ShiftRightLogical(W, 19), Sse2.ShiftLeftLogical(W, 15))), Sse2.ShiftLeftLogical(W, 13));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Schedule(in Vector128<uint> w0, in Vector128<uint> w1, in Vector128<uint> w9, in Vector128<uint> w14, IntPtr i, ref Vector128<uint> schedule)
        {
            Unsafe.Add(ref schedule, i) = Sse2.Add(w0, K128(i));
            return Schedule(w0, w1, w9, w14);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Schedule(in Vector128<uint> w0, in Vector128<uint> w1, in Vector128<uint> w9, in Vector128<uint> w14)
        {
            return Sse2.Add(Sse2.Add(w0, w9), Sse2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private unsafe void Schedule(ref Vector128<uint> schedule, ref byte message)
        {
            Vector128<uint> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            W0 = Ssse3.Shuffle(Gather(ref message).AsByte(), _littleEndianMask128).AsUInt32();
            W1 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 1)).AsByte(), _littleEndianMask128).AsUInt32();
            W2 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 2)).AsByte(), _littleEndianMask128).AsUInt32();
            W3 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 3)).AsByte(), _littleEndianMask128).AsUInt32();
            W4 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 4)).AsByte(), _littleEndianMask128).AsUInt32();
            W5 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 5)).AsByte(), _littleEndianMask128).AsUInt32();
            W6 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 6)).AsByte(), _littleEndianMask128).AsUInt32();
            W7 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 7)).AsByte(), _littleEndianMask128).AsUInt32();
            W8 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 8)).AsByte(), _littleEndianMask128).AsUInt32();
            W9 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 9)).AsByte(), _littleEndianMask128).AsUInt32();
            W10 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 10)).AsByte(), _littleEndianMask128).AsUInt32();
            W11 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 11)).AsByte(), _littleEndianMask128).AsUInt32();
            W12 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 12)).AsByte(), _littleEndianMask128).AsUInt32();
            W13 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 13)).AsByte(), _littleEndianMask128).AsUInt32();
            W14 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 14)).AsByte(), _littleEndianMask128).AsUInt32();
            W15 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 15)).AsByte(), _littleEndianMask128).AsUInt32();

            SchedulStep1(ref schedule, ref W0, ref W1, ref W2, ref W3, ref W4, ref W5, ref W6, ref W7, ref W8, ref W9, ref W10, ref W11, ref W12, ref W13, ref W14, ref W15);

            ScheduleStep2(ref schedule, ref W0, ref W1, ref W2, ref W3, ref W4, ref W5, ref W6, ref W7, ref W8, ref W9, ref W10, ref W11, ref W12, ref W13, ref W14, ref W15);
        }

        private static unsafe void SchedulStep1(ref Vector128<uint> schedule, ref Vector128<uint> W0, ref Vector128<uint> W1, ref Vector128<uint> W2, ref Vector128<uint> W3, ref Vector128<uint> W4, ref Vector128<uint> W5, ref Vector128<uint> W6, ref Vector128<uint> W7, ref Vector128<uint> W8, ref Vector128<uint> W9, ref Vector128<uint> W10, ref Vector128<uint> W11, ref Vector128<uint> W12, ref Vector128<uint> W13, ref Vector128<uint> W14, ref Vector128<uint> W15)
        {
            W0 = Schedule(W0, W1, W9, W14, (IntPtr)0, ref schedule);
            W1 = Schedule(W1, W2, W10, W15, (IntPtr)1, ref schedule);
            W2 = Schedule(W2, W3, W11, W0, (IntPtr)2, ref schedule);
            W3 = Schedule(W3, W4, W12, W1, (IntPtr)3, ref schedule);
            W4 = Schedule(W4, W5, W13, W2, (IntPtr)4, ref schedule);
            W5 = Schedule(W5, W6, W14, W3, (IntPtr)5, ref schedule);
            W6 = Schedule(W6, W7, W15, W4, (IntPtr)6, ref schedule);
            W7 = Schedule(W7, W8, W0, W5, (IntPtr)7, ref schedule);
            W8 = Schedule(W8, W9, W1, W6, (IntPtr)8, ref schedule);
            W9 = Schedule(W9, W10, W2, W7, (IntPtr)9, ref schedule);
            W10 = Schedule(W10, W11, W3, W8, (IntPtr)10, ref schedule);
            W11 = Schedule(W11, W12, W4, W9, (IntPtr)11, ref schedule);
            W12 = Schedule(W12, W13, W5, W10, (IntPtr)12, ref schedule);
            W13 = Schedule(W13, W14, W6, W11, (IntPtr)13, ref schedule);
            W14 = Schedule(W14, W15, W7, W12, (IntPtr)14, ref schedule);
            W15 = Schedule(W15, W0, W8, W13, (IntPtr)15, ref schedule);

            W0 = Schedule(W0, W1, W9, W14, (IntPtr)16, ref schedule);
            W1 = Schedule(W1, W2, W10, W15, (IntPtr)17, ref schedule);
            W2 = Schedule(W2, W3, W11, W0, (IntPtr)18, ref schedule);
            W3 = Schedule(W3, W4, W12, W1, (IntPtr)19, ref schedule);
            W4 = Schedule(W4, W5, W13, W2, (IntPtr)20, ref schedule);
            W5 = Schedule(W5, W6, W14, W3, (IntPtr)21, ref schedule);
            W6 = Schedule(W6, W7, W15, W4, (IntPtr)22, ref schedule);
            W7 = Schedule(W7, W8, W0, W5, (IntPtr)23, ref schedule);
            W8 = Schedule(W8, W9, W1, W6, (IntPtr)24, ref schedule);
            W9 = Schedule(W9, W10, W2, W7, (IntPtr)24, ref schedule);
            W10 = Schedule(W10, W11, W3, W8, (IntPtr)26, ref schedule);
            W11 = Schedule(W11, W12, W4, W9, (IntPtr)27, ref schedule);
            W12 = Schedule(W12, W13, W5, W10, (IntPtr)28, ref schedule);
            W13 = Schedule(W13, W14, W6, W11, (IntPtr)29, ref schedule);
            W14 = Schedule(W14, W15, W7, W12, (IntPtr)30, ref schedule);
            W15 = Schedule(W15, W0, W8, W13, (IntPtr)31, ref schedule);
        }

        private static unsafe void ScheduleStep2(ref Vector128<uint> schedule, ref Vector128<uint> W0, ref Vector128<uint> W1, ref Vector128<uint> W2, ref Vector128<uint> W3, ref Vector128<uint> W4, ref Vector128<uint> W5, ref Vector128<uint> W6, ref Vector128<uint> W7, ref Vector128<uint> W8, ref Vector128<uint> W9, ref Vector128<uint> W10, ref Vector128<uint> W11, ref Vector128<uint> W12, ref Vector128<uint> W13, ref Vector128<uint> W14, ref Vector128<uint> W15)
        {
            Unsafe.Add(ref schedule, 32) = Sse2.Add(W0, K128(K32));
            W0 = Schedule(W0, W1, W9, W14);
            Unsafe.Add(ref schedule, 48) = Sse2.Add(W0, K128(K48));
            Unsafe.Add(ref schedule, 33) = Sse2.Add(W0, K128(K33));
            W1 = Schedule(W1, W2, W10, W15);
            Unsafe.Add(ref schedule, 49) = Sse2.Add(W1, K128(K49));
            Unsafe.Add(ref schedule, 34) = Sse2.Add(W0, K128(K34));
            W2 = Schedule(W2, W3, W11, W0);
            Unsafe.Add(ref schedule, 50) = Sse2.Add(W2, K128(K50));
            Unsafe.Add(ref schedule, 35) = Sse2.Add(W0, K128(K35));
            W3 = Schedule(W3, W4, W12, W1);
            Unsafe.Add(ref schedule, 51) = Sse2.Add(W3, K128(K51));
            Unsafe.Add(ref schedule, 36) = Sse2.Add(W0, K128(K36));
            W4 = Schedule(W4, W5, W13, W2);
            Unsafe.Add(ref schedule, 52) = Sse2.Add(W4, K128(K52));
            Unsafe.Add(ref schedule, 37) = Sse2.Add(W0, K128(K37));
            W5 = Schedule(W5, W6, W14, W3);
            Unsafe.Add(ref schedule, 53) = Sse2.Add(W5, K128(K53));
            Unsafe.Add(ref schedule, 38) = Sse2.Add(W0, K128(K38));
            W6 = Schedule(W6, W7, W15, W4);
            Unsafe.Add(ref schedule, 54) = Sse2.Add(W6, K128(K54));
            Unsafe.Add(ref schedule, 39) = Sse2.Add(W0, K128(K39));
            W7 = Schedule(W7, W8, W0, W5);
            Unsafe.Add(ref schedule, 55) = Sse2.Add(W7, K128(K55));
            Unsafe.Add(ref schedule, 40) = Sse2.Add(W0, K128(K40));
            W8 = Schedule(W8, W9, W1, W6);
            Unsafe.Add(ref schedule, 56) = Sse2.Add(W8, K128(K56));
            Unsafe.Add(ref schedule, 41) = Sse2.Add(W0, K128(K41));
            W9 = Schedule(W9, W10, W2, W7);
            Unsafe.Add(ref schedule, 57) = Sse2.Add(W9, K128(K57));
            Unsafe.Add(ref schedule, 42) = Sse2.Add(W0, K128(K42));
            W10 = Schedule(W10, W11, W3, W8);
            Unsafe.Add(ref schedule, 58) = Sse2.Add(W10, K128(K58));
            Unsafe.Add(ref schedule, 43) = Sse2.Add(W0, K128(K43));
            W11 = Schedule(W11, W12, W4, W9);
            Unsafe.Add(ref schedule, 59) = Sse2.Add(W11, K128(K59));
            Unsafe.Add(ref schedule, 44) = Sse2.Add(W0, K128(K44));
            W12 = Schedule(W12, W13, W5, W10);
            Unsafe.Add(ref schedule, 60) = Sse2.Add(W12, K128(K60));
            Unsafe.Add(ref schedule, 45) = Sse2.Add(W0, K128(K45));
            W13 = Schedule(W13, W14, W6, W11);
            Unsafe.Add(ref schedule, 61) = Sse2.Add(W13, K128(K61));
            Unsafe.Add(ref schedule, 46) = Sse2.Add(W0, K128(K46));
            W14 = Schedule(W14, W15, W7, W12);
            Unsafe.Add(ref schedule, 62) = Sse2.Add(W14, K128(K62));
            Unsafe.Add(ref schedule, 47) = Sse2.Add(W0, K128(K47));
            W15 = Schedule(W15, W0, W8, W13);
            Unsafe.Add(ref schedule, 63) = Sse2.Add(W15, K128(K63));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private void Transform(ref uint state, ref byte currentBlock, ref Vector128<uint> w)
        {
            ref uint wEnd = ref Unsafe.As<Vector128<uint>, uint>(ref Unsafe.Add(ref w, 64));
            uint a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (int j = 0; j < 4; j++)
            {
                a = state;
                b = Unsafe.Add(ref state, 1);
                c = Unsafe.Add(ref state, 2);
                d = Unsafe.Add(ref state, 3);
                e = Unsafe.Add(ref state, 4);
                f = Unsafe.Add(ref state, 5);
                g = Unsafe.Add(ref state, 6);
                h = Unsafe.Add(ref state, 7);
                ref uint w0 = ref Unsafe.Add(ref Unsafe.As<Vector128<uint>, uint>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.Add(ref state, 1) += b;
                Unsafe.Add(ref state, 2) += c;
                Unsafe.Add(ref state, 3) += d;
                Unsafe.Add(ref state, 4) += e;
                Unsafe.Add(ref state, 5) += f;
                Unsafe.Add(ref state, 6) += g;
                Unsafe.Add(ref state, 7) += h;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w)
        {
            h += BigSigma1(e) + Ch(e, f, g) + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }
#endif

        private void Transform(ref uint state, ref byte currentBlock, ref uint w)
        {
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            ref byte wRef = ref Unsafe.As<uint, byte>(ref w);
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), LittleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), _littleEndianMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref currentBlock, j)));
                }
            }

            ref uint wEnd = ref Unsafe.Add(ref w, 64);
            ref uint w0 = ref Unsafe.Add(ref w, 16);
            do
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            uint a = state;
            uint b = Unsafe.Add(ref state, 1);
            uint c = Unsafe.Add(ref state, 2);
            uint d = Unsafe.Add(ref state, 3);
            uint e = Unsafe.Add(ref state, 4);
            uint f = Unsafe.Add(ref state, 5);
            uint g = Unsafe.Add(ref state, 6);
            uint h = Unsafe.Add(ref state, 7);
            w0 = ref w;
            ref uint k0 = ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(K));
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.Add(ref state, 1) += b;
            Unsafe.Add(ref state, 2) += c;
            Unsafe.Add(ref state, 3) += d;
            Unsafe.Add(ref state, 4) += e;
            Unsafe.Add(ref state, 5) += f;
            Unsafe.Add(ref state, 6) += g;
            Unsafe.Add(ref state, 7) += h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w, uint k)
        {
            h += BigSigma1(e) + Ch(e, f, g) + k + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateRight(uint a, byte b)
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
            => BitOperations.RotateRight(a, b);
#else
            => (a >> b) | (a << (32 - b));
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma0(uint a)
            => RotateRight(RotateRight(RotateRight(a, 9) ^ a, 11) ^ a, 2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BigSigma1(uint e)
              => RotateRight(RotateRight(RotateRight(e, 14) ^ e, 5) ^ e, 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma1(uint x)
            => RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Sigma0(uint x)
            => RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Ch(uint x, uint y, uint z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Maj(uint x, uint y, uint z)
            => ((x | y) & z) | (x & y);

        private static ReadOnlySpan<byte> K => new byte[64 * 4] {
            152, 47, 138, 66,
            145, 68, 55, 113,
            207, 251, 192, 181,
            165, 219, 181, 233,
            91, 194, 86, 57,
            241, 17, 241, 89,
            164, 130, 63, 146,
            213, 94, 28, 171,
            152, 170, 7, 216,
            1, 91, 131, 18,
            190, 133, 49, 36,
            195, 125, 12, 85,
            116, 93, 190, 114,
            254, 177, 222, 128,
            167, 6, 220, 155,
            116, 241, 155, 193,
            193, 105, 155, 228,
            134, 71, 190, 239,
            198, 157, 193, 15,
            204, 161, 12, 36,
            111, 44, 233, 45,
            170, 132, 116, 74,
            220, 169, 176, 92,
            218, 136, 249, 118,
            82, 81, 62, 152,
            109, 198, 49, 168,
            200, 39, 3, 176,
            199, 127, 89, 191,
            243, 11, 224, 198,
            71, 145, 167, 213,
            81, 99, 202, 6,
            103, 41, 41, 20,
            133, 10, 183, 39,
            56, 33, 27, 46,
            252, 109, 44, 77,
            19, 13, 56, 83,
            84, 115, 10, 101,
            187, 10, 106, 118,
            46, 201, 194, 129,
            133, 44, 114, 146,
            161, 232, 191, 162,
            75, 102, 26, 168,
            112, 139, 75, 194,
            163, 81, 108, 199,
            25, 232, 146, 209,
            36, 6, 153, 214,
            133, 53, 14, 244,
            112, 160, 106, 16,
            22, 193, 164, 25,
            8, 108, 55, 30,
            76, 119, 72, 39,
            181, 188, 176, 52,
            179, 12, 28, 57,
            74, 170, 216, 78,
            79, 202, 156, 91,
            243, 111, 46, 104,
            238, 130, 143, 116,
            111, 99, 165, 120,
            20, 120, 200, 132,
            8, 2, 199, 140,
            250, 255, 190, 144,
            235, 108, 80, 164,
            247, 163, 249, 190,
            242, 120, 113, 198
        };


        private static ReadOnlySpan<byte> K0 => new byte[4] {
            152, 47, 138, 66,
        };
        private static ReadOnlySpan<byte> K1 => new byte[4] {
            145, 68, 55, 113,
        };
        private static ReadOnlySpan<byte> K2 => new byte[4] {
            207, 251, 192, 181,
            };
        private static ReadOnlySpan<byte> K3 => new byte[4] {
            165, 219, 181, 233,        };
        private static ReadOnlySpan<byte> K4 => new byte[4] {
            91, 194, 86, 57,        };
        private static ReadOnlySpan<byte> K5 => new byte[4] {
            241, 17, 241, 89,        };
        private static ReadOnlySpan<byte> K6 => new byte[4] {
            164, 130, 63, 146,        };
        private static ReadOnlySpan<byte> K7 => new byte[4] {
            213, 94, 28, 171,        };
        private static ReadOnlySpan<byte> K8 => new byte[4] {
            152, 170, 7, 216,        };
        private static ReadOnlySpan<byte> K9 => new byte[4] {
            1, 91, 131, 18,        };
        private static ReadOnlySpan<byte> K10 => new byte[4] {
            190, 133, 49, 36,        };
        private static ReadOnlySpan<byte> K11 => new byte[4] {
            195, 125, 12, 85,        };
        private static ReadOnlySpan<byte> K12 => new byte[4] {
            116, 93, 190, 114,        };
        private static ReadOnlySpan<byte> K13 => new byte[4] {
            254, 177, 222, 128,        };
        private static ReadOnlySpan<byte> K14 => new byte[4] {
            167, 6, 220, 155,        };
        private static ReadOnlySpan<byte> K15 => new byte[4] {
            116, 241, 155, 193,        };
        private static ReadOnlySpan<byte> K16 => new byte[4] {
            193, 105, 155, 228,        };
        private static ReadOnlySpan<byte> K17 => new byte[4] {
            134, 71, 190, 239,        };
        private static ReadOnlySpan<byte> K18 => new byte[4] {
            198, 157, 193, 15,        };
        private static ReadOnlySpan<byte> K19 => new byte[4] {
            204, 161, 12, 36,        };
        private static ReadOnlySpan<byte> K20 => new byte[4] {
            111, 44, 233, 45,        };
        private static ReadOnlySpan<byte> K21 => new byte[4] {
            170, 132, 116, 74,        };
        private static ReadOnlySpan<byte> K22 => new byte[4] {
            220, 169, 176, 92,        };
        private static ReadOnlySpan<byte> K23 => new byte[4] {
            218, 136, 249, 118,        };
        private static ReadOnlySpan<byte> K24 => new byte[4] {
            82, 81, 62, 152,        };
        private static ReadOnlySpan<byte> K25 => new byte[4] {
            109, 198, 49, 168,        };
        private static ReadOnlySpan<byte> K26 => new byte[4] {
            200, 39, 3, 176,        };
        private static ReadOnlySpan<byte> K27 => new byte[4] {
            199, 127, 89, 191,        };
        private static ReadOnlySpan<byte> K28 => new byte[4] {
            243, 11, 224, 198,        };
        private static ReadOnlySpan<byte> K29 => new byte[4] {
            71, 145, 167, 213,        };
        private static ReadOnlySpan<byte> K30 => new byte[4] {
            81, 99, 202, 6,        };
        private static ReadOnlySpan<byte> K31 => new byte[4] {
            103, 41, 41, 20,        };
        private static ReadOnlySpan<byte> K32 => new byte[4] {
            133, 10, 183, 39,        };
        private static ReadOnlySpan<byte> K33 => new byte[4] {
            56, 33, 27, 46,        };
        private static ReadOnlySpan<byte> K34 => new byte[4] {
            252, 109, 44, 77,        };
        private static ReadOnlySpan<byte> K35 => new byte[4] {
            19, 13, 56, 83,        };
        private static ReadOnlySpan<byte> K36 => new byte[4] {
            84, 115, 10, 101,        };
        private static ReadOnlySpan<byte> K37 => new byte[4] {
            187, 10, 106, 118,        };
        private static ReadOnlySpan<byte> K38 => new byte[4] {
            46, 201, 194, 129,        };
        private static ReadOnlySpan<byte> K39 => new byte[4] {
            133, 44, 114, 146,        };
        private static ReadOnlySpan<byte> K40 => new byte[4] {
            161, 232, 191, 162,        };
        private static ReadOnlySpan<byte> K41 => new byte[4] {
            75, 102, 26, 168,        };
        private static ReadOnlySpan<byte> K42 => new byte[4] {
            112, 139, 75, 194,        };
        private static ReadOnlySpan<byte> K43 => new byte[4] {
            163, 81, 108, 199,        };
        private static ReadOnlySpan<byte> K44 => new byte[4] {
            25, 232, 146, 209,        };
        private static ReadOnlySpan<byte> K45 => new byte[4] {
            36, 6, 153, 214,        };
        private static ReadOnlySpan<byte> K46 => new byte[4] {
            133, 53, 14, 244,        };
        private static ReadOnlySpan<byte> K47 => new byte[4] {
            112, 160, 106, 16,        };
        private static ReadOnlySpan<byte> K48 => new byte[4] {
            22, 193, 164, 25,        };
        private static ReadOnlySpan<byte> K49 => new byte[4] {
            8, 108, 55, 30,        };
        private static ReadOnlySpan<byte> K50 => new byte[4] {
            76, 119, 72, 39,        };
        private static ReadOnlySpan<byte> K51 => new byte[4] {
            181, 188, 176, 52,        };
        private static ReadOnlySpan<byte> K52 => new byte[4] {
            179, 12, 28, 57,        };
        private static ReadOnlySpan<byte> K53 => new byte[4] {
            74, 170, 216, 78,        };
        private static ReadOnlySpan<byte> K54 => new byte[4] {
            79, 202, 156, 91,        };
        private static ReadOnlySpan<byte> K55 => new byte[4] {
            243, 111, 46, 104,        };
        private static ReadOnlySpan<byte> K56 => new byte[4] {
            238, 130, 143, 116,        };
        private static ReadOnlySpan<byte> K57 => new byte[4] {
            111, 99, 165, 120,        };
        private static ReadOnlySpan<byte> K58 => new byte[4] {
            20, 120, 200, 132,        };
        private static ReadOnlySpan<byte> K59 => new byte[4] {
            8, 2, 199, 140,        };
        private static ReadOnlySpan<byte> K60 => new byte[4] {
            250, 255, 190, 144,        };
        private static ReadOnlySpan<byte> K61 => new byte[4] {
            235, 108, 80, 164,        };
        private static ReadOnlySpan<byte> K62 => new byte[4] {
            247, 163, 249, 190,        };
        private static ReadOnlySpan<byte> K63 => new byte[4] {
            242, 120, 113, 198
        };

#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_2
        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> LittleEndianMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _littleEndianMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> K128(IntPtr i)
            => Vector128.Create(Unsafe.Add(ref Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(K)), i));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> K128(ReadOnlySpan<byte> ros)
            => Vector128.Create(Unsafe.As<byte, uint>(ref MemoryMarshal.GetReference(ros)));

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static readonly Vector256<byte> _shuffleMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static readonly Vector128<byte> _shuffleMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

#endif
    }
}
