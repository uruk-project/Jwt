using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NETCOREAPP3_0
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Computes SHA2-256 hash values.
    /// </summary>
    public class Sha256 : ShaAlgorithm
    {
        /// <inheritsdoc />
        public override int HashSize => 32;

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend = default)
        {
            const int BlockSize = 64;
            Debug.Assert(destination.Length == 32);

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

            // update
            Span<uint> W = stackalloc uint[64];
            ref uint w = ref MemoryMarshal.GetReference(W);
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            if (!prepend.IsEmpty)
            {
                Debug.Assert(prepend.Length == BlockSize);
                Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref w);
            }

            ref byte srcRef = ref MemoryMarshal.GetReference(source);
            ref byte srcEndRef = ref Unsafe.Add(ref srcRef, source.Length - BlockSize + 1);
#if NETCOREAPP3_0
            if (Ssse3.IsSupported)
            {
                ref byte srcSseEndRef = ref Unsafe.Add(ref srcRef, source.Length - 4 * BlockSize + 1);
                if (Unsafe.IsAddressLessThan(ref srcRef, ref srcSseEndRef))
                {
                    Vector128<uint>[] returnToPool;
                    Span<Vector128<uint>> wSse = (returnToPool = ArrayPool<Vector128<uint>>.Shared.Rent(64));
                    try
                    {
                        ref Vector128<uint> wRef = ref MemoryMarshal.GetReference(wSse);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref wRef);
                            srcRef = ref Unsafe.Add(ref srcRef, BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref srcSseEndRef));
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
                Transform(ref stateRef, ref srcRef, ref w);
                srcRef = ref Unsafe.Add(ref srcRef, BlockSize);
            }

            // final
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (BlockSize - 1);

            Span<byte> lastBlock = stackalloc byte[BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);

            // Pad the last block
            Unsafe.Add(ref lastBlockRef, remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= BlockSize - sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref w);
                lastBlock.Slice(0, BlockSize - sizeof(ulong)).Clear();
            }

            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, BlockSize - sizeof(ulong)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref w);

            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if NETCOREAPP3_0
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

#if NETCOREAPP3_0
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
            Unsafe.Add(ref schedule, i) = Sse2.Add(w0, KSse(i));
            return Sse2.Add(Sse2.Add(w0, w9), Sse2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private void Schedule(ref Vector128<uint> schedule, ref byte message)
        {
            Vector128<uint> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            W0 = Ssse3.Shuffle(Gather(ref message).AsByte(), LittleEndianMask128).AsUInt32();
            W1 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 1)).AsByte(), LittleEndianMask128).AsUInt32();
            W2 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 2)).AsByte(), LittleEndianMask128).AsUInt32();
            W3 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 3)).AsByte(), LittleEndianMask128).AsUInt32();
            W4 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 4)).AsByte(), LittleEndianMask128).AsUInt32();
            W5 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 5)).AsByte(), LittleEndianMask128).AsUInt32();
            W6 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 6)).AsByte(), LittleEndianMask128).AsUInt32();
            W7 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 7)).AsByte(), LittleEndianMask128).AsUInt32();
            W8 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 8)).AsByte(), LittleEndianMask128).AsUInt32();
            W9 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 9)).AsByte(), LittleEndianMask128).AsUInt32();
            W10 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 10)).AsByte(), LittleEndianMask128).AsUInt32();
            W11 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 11)).AsByte(), LittleEndianMask128).AsUInt32();
            W12 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 12)).AsByte(), LittleEndianMask128).AsUInt32();
            W13 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 13)).AsByte(), LittleEndianMask128).AsUInt32();
            W14 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 14)).AsByte(), LittleEndianMask128).AsUInt32();
            W15 = Ssse3.Shuffle(Gather(ref Unsafe.Add(ref message, 4 * 15)).AsByte(), LittleEndianMask128).AsUInt32();
            int i = 0;
            while (i < 32)
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

            W0 = Schedule(W0, W1, W9, W14, i++, ref schedule);
            Unsafe.Add(ref schedule, 48) = Sse2.Add(W0, KSse(48));
            W1 = Schedule(W1, W2, W10, W15, i++, ref schedule);
            Unsafe.Add(ref schedule, 49) = Sse2.Add(W1, KSse(49));
            W2 = Schedule(W2, W3, W11, W0, i++, ref schedule);
            Unsafe.Add(ref schedule, 50) = Sse2.Add(W2, KSse(50));
            W3 = Schedule(W3, W4, W12, W1, i++, ref schedule);
            Unsafe.Add(ref schedule, 51) = Sse2.Add(W3, KSse(51));
            W4 = Schedule(W4, W5, W13, W2, i++, ref schedule);
            Unsafe.Add(ref schedule, 52) = Sse2.Add(W4, KSse(52));
            W5 = Schedule(W5, W6, W14, W3, i++, ref schedule);
            Unsafe.Add(ref schedule, 53) = Sse2.Add(W5, KSse(53));
            W6 = Schedule(W6, W7, W15, W4, i++, ref schedule);
            Unsafe.Add(ref schedule, 54) = Sse2.Add(W6, KSse(54));
            W7 = Schedule(W7, W8, W0, W5, i++, ref schedule);
            Unsafe.Add(ref schedule, 55) = Sse2.Add(W7, KSse(55));
            W8 = Schedule(W8, W9, W1, W6, i++, ref schedule);
            Unsafe.Add(ref schedule, 56) = Sse2.Add(W8, KSse(56));
            W9 = Schedule(W9, W10, W2, W7, i++, ref schedule);
            Unsafe.Add(ref schedule, 57) = Sse2.Add(W9, KSse(57));
            W10 = Schedule(W10, W11, W3, W8, i++, ref schedule);
            Unsafe.Add(ref schedule, 58) = Sse2.Add(W10, KSse(58));
            W11 = Schedule(W11, W12, W4, W9, i++, ref schedule);
            Unsafe.Add(ref schedule, 59) = Sse2.Add(W11, KSse(59));
            W12 = Schedule(W12, W13, W5, W10, i++, ref schedule);
            Unsafe.Add(ref schedule, 60) = Sse2.Add(W12, KSse(60));
            W13 = Schedule(W13, W14, W6, W11, i++, ref schedule);
            Unsafe.Add(ref schedule, 61) = Sse2.Add(W13, KSse(61));
            W14 = Schedule(W14, W15, W7, W12, i++, ref schedule);
            Unsafe.Add(ref schedule, 62) = Sse2.Add(W14, KSse(62));
            W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
            Unsafe.Add(ref schedule, 63) = Sse2.Add(W15, KSse(63));
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private void Transform(ref uint state, ref byte currentBlock, ref Vector128<uint> w)
        {
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
                for (int t = 0; t < 64; t += 8)
                {
                    Round(a, b, c, ref d, e, f, g, ref h, Unsafe.Add(ref w, t).GetElement(j));
                    Round(h, a, b, ref c, d, e, f, ref g, Unsafe.Add(ref w, t + 1).GetElement(j));
                    Round(g, h, a, ref b, c, d, e, ref f, Unsafe.Add(ref w, t + 2).GetElement(j));
                    Round(f, g, h, ref a, b, c, d, ref e, Unsafe.Add(ref w, t + 3).GetElement(j));
                    Round(e, f, g, ref h, a, b, c, ref d, Unsafe.Add(ref w, t + 4).GetElement(j));
                    Round(d, e, f, ref g, h, a, b, ref c, Unsafe.Add(ref w, t + 5).GetElement(j));
                    Round(c, d, e, ref f, g, h, a, ref b, Unsafe.Add(ref w, t + 6).GetElement(j));
                    Round(b, c, d, ref e, f, g, h, ref a, Unsafe.Add(ref w, t + 7).GetElement(j));
                }

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
#if NETCOREAPP3_0
            ref byte wRef = ref Unsafe.As<uint, byte>(ref w);
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), LittleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), LittleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), LittleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), LittleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), LittleEndianMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref currentBlock, j)));
                }
            }

            ref uint w0 = ref Unsafe.Add(ref w, 16);
            ref uint wEnd = ref Unsafe.Add(ref w, 64);
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd))
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }

            uint a = state;
            uint b = Unsafe.Add(ref state, 1);
            uint c = Unsafe.Add(ref state, 2);
            uint d = Unsafe.Add(ref state, 3);
            uint e = Unsafe.Add(ref state, 4);
            uint f = Unsafe.Add(ref state, 5);
            uint g = Unsafe.Add(ref state, 6);
            uint h = Unsafe.Add(ref state, 7);

            for (int i = 0; i < 64; i += 8)
            {
                Round(a, b, c, ref d, e, f, g, ref h, Unsafe.Add(ref w, i), K(i));
                Round(h, a, b, ref c, d, e, f, ref g, Unsafe.Add(ref w, i + 1), K(i + 1));
                Round(g, h, a, ref b, c, d, e, ref f, Unsafe.Add(ref w, i + 2), K(i + 2));
                Round(f, g, h, ref a, b, c, d, ref e, Unsafe.Add(ref w, i + 3), K(i + 3));
                Round(e, f, g, ref h, a, b, c, ref d, Unsafe.Add(ref w, i + 4), K(i + 4));
                Round(d, e, f, ref g, h, a, b, ref c, Unsafe.Add(ref w, i + 5), K(i + 5));
                Round(c, d, e, ref f, g, h, a, ref b, Unsafe.Add(ref w, i + 6), K(i + 6));
                Round(b, c, d, ref e, f, g, h, ref a, Unsafe.Add(ref w, i + 7), K(i + 7));
            }

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
#if NETCOREAPP3_0
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ref uint K(int i) => ref Unsafe.Add(ref k[0], i);

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

#if NETCOREAPP3_0
        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        private static Vector256<byte> LittleEndianMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static Vector128<byte> LittleEndianMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> KSse(int i) => Unsafe.Add(ref kSse[0], i);

        private static readonly Vector128<uint>[] kSse = {
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
        private static Vector256<byte> _shuffleMask256 = Vector256.Create(
                289644378169868803,
                868365760874482187,
                1447087143579095571,
                2025808526283708955
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        private static Vector128<byte> _shuffleMask128 = Vector128.Create(
                289644378169868803,
                868365760874482187
                ).AsByte();

#endif

    }
}
