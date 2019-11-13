using System;
#if NETCOREAPP3_0
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using a SHA2 hash function.
    /// </summary>
    public abstract class HmacSha
    {
#if NETCOREAPP3_0
        private static readonly Vector256<byte> _innerKeyInit = Vector256.Create((byte)0x36);
        private static readonly Vector256<byte> _outerKeyInit = Vector256.Create((byte)0x5c);
#endif  
        /// <summary>
        /// The hash algorithm.
        /// </summary>
        protected readonly ShaAlgorithm _sha;

        /// <summary>
        /// The inner &amp; outer pad keys.
        /// </summary>
        protected readonly byte[] _keys;

        /// <summary>
        /// The inner pad key.
        /// </summary>
        protected ReadOnlySpan<byte> InnerPadKey => new ReadOnlySpan<byte>(_keys, 0, BlockSize);

        /// <summary>
        /// The outer pad key.
        /// </summary>
        protected ReadOnlySpan<byte> OuterPadKey => new ReadOnlySpan<byte>(_keys, BlockSize, BlockSize);

        /// <summary>
        /// The block size.
        /// </summary>
        public abstract int BlockSize { get; }

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public int HashSize => _sha.HashSize;

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha"/> class.
        /// </summary>
        /// <param name="sha"></param>
        /// <param name="key"></param>
        protected HmacSha(ShaAlgorithm sha, ReadOnlySpan<byte> key)
        {
            _keys = new byte[BlockSize * 2];
            _sha = sha;
            if (key.Length > BlockSize)
            {
                Span<byte> keyPrime = stackalloc byte[sha.HashSize];
                _sha.ComputeHash(key, keyPrime);
                InitializeIOKeys(sha, keyPrime);
                keyPrime.Clear();
            }
            else
            {
                InitializeIOKeys(sha, key);
            }
        }

        private void InitializeIOKeys(ShaAlgorithm sha, ReadOnlySpan<byte> key)
        {
#if NETCOREAPP3_0
            if (Avx2.IsSupported && (key.Length & 31) == 0)
            {
                ref byte keyRef = ref MemoryMarshal.GetReference(key);
                ref byte keyEndRef = ref Unsafe.Add(ref keyRef, key.Length);
                ref byte innerKeyRef = ref Unsafe.AsRef(_keys[0]);
                ref byte outerKeyRef = ref Unsafe.Add(ref innerKeyRef, BlockSize);
                ref byte innerKeyEndRef = ref outerKeyRef;
                if (Unsafe.IsAddressLessThan(ref keyRef, ref keyEndRef))
                {
                    do
                    {
                        var k1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref keyRef);
                        Unsafe.WriteUnaligned(ref innerKeyRef, Avx2.Xor(k1, _innerKeyInit));
                        Unsafe.WriteUnaligned(ref outerKeyRef, Avx2.Xor(k1, _outerKeyInit));

                        // assume the IO keys are Modulo 32
                        keyRef = ref Unsafe.Add(ref keyRef, 32);
                        innerKeyRef = ref Unsafe.Add(ref innerKeyRef, 32);
                        outerKeyRef = ref Unsafe.Add(ref outerKeyRef, 32);
                    } while (Unsafe.IsAddressLessThan(ref keyRef, ref keyEndRef));
                }

                // treat the remain
                while (Unsafe.IsAddressLessThan(ref innerKeyRef, ref innerKeyEndRef))
                {
                    Unsafe.WriteUnaligned(ref innerKeyRef, _innerKeyInit);
                    Unsafe.WriteUnaligned(ref outerKeyRef, _outerKeyInit);
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
                    _keys[i] = (byte)(key[i] ^ 0x36);
                    _keys[i + BlockSize] = (byte)(key[i] ^ 0x5c);
                    i++;
                }

                while (i < BlockSize)
                {
                    _keys[i] ^= 0x36;
                    _keys[i + BlockSize] ^= 0x5c;
                    i++;
                }
            }
        }

        /// <summary>
        /// Computes the hash value.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="destination"></param>
        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));
            _sha.ComputeHash(source, destination, InnerPadKey);
            _sha.ComputeHash(destination, destination, OuterPadKey);
        }

        /// <summary>
        /// Clears the keys.
        /// </summary>
        public void Clear()
        {
            _keys.AsSpan().Clear();
        }
    }
}
