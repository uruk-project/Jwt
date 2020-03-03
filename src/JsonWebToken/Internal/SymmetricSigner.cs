// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.
    /// </summary>
    internal sealed class SymmetricSigner : Signer
    {
        private readonly HmacSha2 _hashAlgorithm;
        private bool _disposed;

        /// <summary>
        /// This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public const int DefaultMinimumSymmetricKeySizeInBits = 128;

        private readonly int _hashSizeInBytes;
        private readonly int _base64HashSizeInBytes;
        private int _minimumKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        public SymmetricSigner(SymmetricJwk key, SignatureAlgorithm algorithm)
            : this(key.AsSpan(), algorithm)
        {
        }

        public SymmetricSigner(ReadOnlySpan<byte> key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            if (key.Length << 3 < MinimumKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(key.Length << 3, algorithm.Name, MinimumKeySizeInBits);
            }

            if (algorithm.Category != AlgorithmCategory.Hmac)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(algorithm);
            }

            _hashSizeInBytes = Algorithm.RequiredKeySizeInBits >> 2;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _hashAlgorithm = Algorithm.Id switch
            {
                Algorithms.HmacSha256 => new HmacSha256(key),
                Algorithms.HmacSha384 => new HmacSha384(key),
                Algorithms.HmacSha512 => new HmacSha512(key),
                _ => new NotSupportedHmacSha(algorithm)
            };
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricJwk"/>.KeySize.
        /// </summary>
        public int MinimumKeySizeInBits
        {
            get
            {
                return _minimumKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.value, DefaultMinimumSymmetricKeySizeInBits);
                }

                _minimumKeySizeInBits = value;
            }
        }

        /// <inheritsdoc />
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            _hashAlgorithm.ComputeHash(input, destination);
            bytesWritten = destination.Length;
            return true;
        }

        /// <inheritsdoc />
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            Span<byte> hash = stackalloc byte[_hashSizeInBytes];
            _hashAlgorithm.ComputeHash(input, hash);
            return AreFixedTimeEqual(signature, hash);
        }

        // Optimized byte-based AreEqual. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool AreFixedTimeEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            int length = a.Length;
            ref byte first = ref MemoryMarshal.GetReference(a);
            ref byte second = ref MemoryMarshal.GetReference(b);
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported && length == 64)
            {
                return
                    Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref first), Unsafe.ReadUnaligned<Vector256<byte>>(ref second))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111)
                 & Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref first, 32)), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref second, 32)))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            else if (Avx2.IsSupported && length == 32)
            {
                return Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref first), Unsafe.ReadUnaligned<Vector256<byte>>(ref second))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            else if (Sse2.IsSupported && length == 16)
            {
                return Sse2.MoveMask(Sse2.CompareEqual(Unsafe.ReadUnaligned<Vector128<byte>>(ref first), Unsafe.ReadUnaligned<Vector128<byte>>(ref second))) == 0b1111_1111_1111_1111;
            }
            else
#endif
            if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count)
            {
                Vector<byte> equals = new Vector<byte>();
                ref byte firstEnd = ref Unsafe.Add(ref first, length - Vector<byte>.Count);
                ref byte secondEnd = ref Unsafe.Add(ref second, length - Vector<byte>.Count);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref first) - Unsafe.ReadUnaligned<Vector<byte>>(ref second);
                    first = ref Unsafe.Add(ref first, Vector<byte>.Count);
                    second = ref Unsafe.Add(ref second, Vector<byte>.Count);
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref firstEnd) - Unsafe.ReadUnaligned<Vector<byte>>(ref secondEnd);
                return equals == Vector<byte>.Zero;
            }
            else if (length >= sizeof(long))
            {
                long equals = 0L;
                ref byte firstEnd = ref Unsafe.Add(ref first, length - sizeof(long));
                ref byte secondEnd = ref Unsafe.Add(ref second, length - sizeof(long));
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= Unsafe.ReadUnaligned<long>(ref first) - Unsafe.ReadUnaligned<long>(ref second);
                    first = ref Unsafe.Add(ref first, sizeof(long));
                    second = ref Unsafe.Add(ref second, sizeof(long));
                }

                equals |= Unsafe.ReadUnaligned<long>(ref firstEnd) - Unsafe.ReadUnaligned<long>(ref secondEnd);
                return equals == 0L;
            }
            else
            {
                int equals = 0;
                ref byte firstEnd = ref Unsafe.Add(ref first, length);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    equals |= first - second;
                    first = ref Unsafe.Add(ref first, 1);
                    second = ref Unsafe.Add(ref second, 1);
                }

                return equals == 0;
            }
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithm.Clear();
                }

                _disposed = true;
            }
        }

        private sealed class NotSupportedHmacSha : HmacSha2
        {
            public NotSupportedHmacSha(SignatureAlgorithm algorithm)
                : base(ShaNull.Shared, default)
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm.Name);
            }
        }

        private sealed class ShaNull : Sha2
        {
            public static readonly ShaNull Shared = new ShaNull();

            public override int HashSize => 0;

            public override int BlockSize => 0;

            public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<byte> w)
            {
            }

            public override int GetWorkingSetSize(int sourceLength)
            {
                return 0;
            }
        }
    }
}
