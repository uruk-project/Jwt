using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NETCOREAPP3_0
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    public class Hmac : IDisposable
    {
        private readonly Sha256 _sha256;
        private readonly byte[] _innerKey = new byte[64];
        private readonly byte[] _outerKey = new byte[64];

#if NETCOREAPP3_0
        private static readonly Vector256<byte> _innerKeyInit = Vector256.Create((byte)0x36);
        private static readonly Vector256<byte> _outerKeyInit = Vector256.Create((byte)0x5c);
#endif  
        public Hmac(Sha256 sha256, ReadOnlySpan<byte> key)
        {
            _sha256 = sha256;
            Span<byte> keyPrime = stackalloc byte[64];
            if (key.Length > 64)
            {
                _sha256.ComputeHash(key, keyPrime);
            }
            else
            {
                key.CopyTo(keyPrime);
            }

#if NETCOREAPP3_0
            if (Avx2.IsSupported)
            {
                ref byte keyRef = ref MemoryMarshal.GetReference(keyPrime);
                ref byte innerKeyRef = ref Unsafe.AsRef(_innerKey[0]);
                ref byte outerKeyRef = ref Unsafe.AsRef(_outerKey[0]);
                var k1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref keyRef);
                var k2 = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref keyRef, 32));
                Unsafe.WriteUnaligned(ref innerKeyRef, Avx2.Xor(k1, _innerKeyInit));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref innerKeyRef, 32), Avx2.Xor(k2, _innerKeyInit));
                Unsafe.WriteUnaligned(ref outerKeyRef, Avx2.Xor(k1, _outerKeyInit));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref outerKeyRef, 32), Avx2.Xor(k2, _outerKeyInit));
            }
            else
#endif
            {
                int i = 0;
                while (i < key.Length)
                {
                    _innerKey[i] = (byte)(key[i] ^ 0x36);
                    _outerKey[i] = (byte)(key[i] ^ 0x5c);
                    i++;
                }
                for (; i < 64; i++)
                {
                    _innerKey[i] ^= 0x36;
                    _outerKey[i] ^= 0x5c;
                }
            }
        }

        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));
            _sha256.ComputeHash(source, destination, _innerKey);
            _sha256.ComputeHash(destination, destination, _outerKey);
        }

        public void Dispose()
        {
            new Span<byte>(_innerKey).Clear();
            new Span<byte>(_outerKey).Clear();
        }
    }
    public class Sha256
    {
        static readonly uint[] k = {
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

        private static readonly Vector256<uint> _initialState = Vector256.Create(0x6a09e667,
                                      0xbb67ae85,
                                      0x3c6ef372,
                                      0xa54ff53a,
                                      0x510e527f,
                                      0x9b05688c,
                                      0x1f83d9ab,
                                      0x5be0cd19);
#endif
        private void Transform(ref uint state, ref byte currentBlock)
        {
            uint a, b, c, d, e, f, g, h;
            Span<uint> w = stackalloc uint[64];
            ref byte wRef = ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetReference(w));

#if NETCOREAPP3_0
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 0)), _shuffleMask256));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _shuffleMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 0)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), _shuffleMask128));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), _shuffleMask128));
            }
            else
#endif
            {
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    w[i] = (uint)((Unsafe.Add(ref currentBlock, j) << 24) | (Unsafe.Add(ref currentBlock, j + 1) << 16) | (Unsafe.Add(ref currentBlock, j + 2) << 8) | (Unsafe.Add(ref currentBlock, j + 3)));
                }
            }

            for (int i = 16; i < 64; i += 2)
            {
                w[i] = w[i - 16] + ShaHelper.Sigma0(w[i - 15]) + w[i - 7] + ShaHelper.Sigma1(w[i - 2]);
                w[i + 1] = w[i - 15] + ShaHelper.Sigma0(w[i - 14]) + w[i - 6] + ShaHelper.Sigma1(w[i - 1]);
            }

            a = state;
            b = Unsafe.Add(ref state, 1);
            c = Unsafe.Add(ref state, 2);
            d = Unsafe.Add(ref state, 3);
            e = Unsafe.Add(ref state, 4);
            f = Unsafe.Add(ref state, 5);
            g = Unsafe.Add(ref state, 6);
            h = Unsafe.Add(ref state, 7);
            for (int i = 0; i < 64; i += 8)
            {
                Round(a, b, c, ref d, e, f, g, ref h, w[i], k[i]);
                Round(h, a, b, ref c, d, e, f, ref g, w[i + 1], k[i + 1]);
                Round(g, h, a, ref b, c, d, e, ref f, w[i + 2], k[i + 2]);
                Round(f, g, h, ref a, b, c, d, ref e, w[i + 3], k[i + 3]);
                Round(e, f, g, ref h, a, b, c, ref d, w[i + 4], k[i + 4]);
                Round(d, e, f, ref g, h, a, b, ref c, w[i + 5], k[i + 5]);
                Round(c, d, e, ref f, g, h, a, ref b, w[i + 6], k[i + 6]);
                Round(b, c, d, ref e, f, g, h, ref a, w[i + 7], k[i + 7]);
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

        public void ComputeHash(ReadOnlySpan<byte> src, Span<byte> destination, ReadOnlySpan<byte> prepend = default)
        {
            Span<uint> state = stackalloc uint[] {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
            };
            ref uint stateRef = ref MemoryMarshal.GetReference(state);
            if (!prepend.IsEmpty)
            {
                Debug.Assert(prepend.Length == 64);
                Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend));
            }

            ref byte srcRef = ref MemoryMarshal.GetReference(src);
            ref byte srcEndRef = ref Unsafe.Add(ref srcRef, src.Length - 64 + 1);
            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef);
                srcRef = ref Unsafe.Add(ref srcRef, 64);
            }

            int dataLength = src.Length + prepend.Length;
            int remaining = dataLength & 63;

            Span<byte> lastBlock = stackalloc byte[64];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);

            // Pad the last block
            Unsafe.Add(ref lastBlockRef, remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= 56)
            {
                Transform(ref stateRef, ref lastBlockRef);
                lastBlock.Slice(0, 56).Clear();
            }

            // Append to the padding the total message's length in bits and transform.
            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, 56), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef);

            // reverse all the bytes when copying the final state to the output hash.
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
                for (int j = 0; j < 4; ++j)
                {
                    destination[j] = (byte)((stateRef >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 4] = (byte)((Unsafe.Add(ref stateRef, 1) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 8] = (byte)((Unsafe.Add(ref stateRef, 2) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 12] = (byte)((Unsafe.Add(ref stateRef, 3) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 16] = (byte)((Unsafe.Add(ref stateRef, 4) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 20] = (byte)((Unsafe.Add(ref stateRef, 5) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 24] = (byte)((Unsafe.Add(ref stateRef, 6) >> (24 - j * 8)) & 0x000000ff);
                    destination[j + 28] = (byte)((Unsafe.Add(ref stateRef, 7) >> (24 - j * 8)) & 0x000000ff);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(uint a, uint b, uint c, ref uint d, uint e, uint f, uint g, ref uint h, uint w, uint k)
        {
            uint t1 = h + ShaHelper.BigSigma1(e) + ShaHelper.Ch(e, f, g) + k + w;
            uint t2 = ShaHelper.BigSigma0(a) + ShaHelper.Maj(a, b, c);
            d += t1;
            h = t1 + t2;
        }
    }

    public static class ShaHelper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotR32(uint a, byte b)
            => (((a) >> (b)) | ((a) << (32 - (b))));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint BigSigma0(uint a)
            => RotR32(RotR32(RotR32(a, 9) ^ a, 11) ^ a, 2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint BigSigma1(uint e)
              => RotR32(RotR32(RotR32(e, 14) ^ e, 5) ^ e, 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sigma1(uint x)
            => RotR32(x, 17) ^ RotR32(x, 19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sigma0(uint x)
            => RotR32(x, 7) ^ RotR32(x, 18) ^ (x >> 3);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ch(uint x, uint y, uint z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Maj(uint x, uint y, uint z)
            => ((x | y) & z) | (x & y);
    }
}
