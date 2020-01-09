// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Defines encryption algorithm.
    /// </summary>
    public sealed class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>, IAlgorithm
    {
        /// <summary>
        /// Empty
        /// </summary>
        internal static readonly EncryptionAlgorithm Empty = new EncryptionAlgorithm(id: 0, "Empty", requiredKeySizeInBytes: 0, SignatureAlgorithm.None, requiredKeyWrappedSizeInBytes: 0, EncryptionType.Undefined);

        /// <summary>
        /// 'A128CBC-HS256'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(id: 11, "A128CBC-HS256", requiredKeySizeInBytes: 32, SignatureAlgorithm.HmacSha256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

        /// <summary>
        /// 'A192CBC-HS384'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(id: 12, "A192CBC-HS384", requiredKeySizeInBytes: 48, SignatureAlgorithm.HmacSha384, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesHmac);

        /// <summary>
        /// 'A256CBC-HS512'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(id: 13, "A256CBC-HS512", requiredKeySizeInBytes: 64, SignatureAlgorithm.HmacSha512, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesHmac);

        /// <summary>
        /// 'A128GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(id: 21, "A128GCM", requiredKeySizeInBytes: 16, hashAlgorithm: null, requiredKeyWrappedSizeInBytes: 24, EncryptionType.AesGcm);

        /// <summary>
        /// 'A192GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(id: 22, "A192GCM", requiredKeySizeInBytes: 24, hashAlgorithm: null, requiredKeyWrappedSizeInBytes: 32, EncryptionType.AesGcm);

        /// <summary>
        /// 'A256GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(id: 23, "A256GCM", requiredKeySizeInBytes: 32, hashAlgorithm: null, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesGcm);

        private static readonly EncryptionAlgorithm[] _algorithms = new[]
        {
            Aes128CbcHmacSha256,
            Aes192CbcHmacSha384,
            Aes256CbcHmacSha512,
            Aes128Gcm,
            Aes192Gcm,
            Aes256Gcm
        };

        private readonly sbyte _id;
        private readonly EncryptionType _category;
        private readonly ushort _requiredKeySizeInBytes;
        private readonly ushort _keyWrappedSizeInBytes;
        private readonly SignatureAlgorithm? _signatureAlgorithm;
        private readonly byte[] _utf8Name;

        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id => _id;

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public EncryptionType Category => _category;

        /// <summary>
        /// Gets the required key size, in bytes.
        /// </summary>
        public ushort RequiredKeySizeInBytes => _requiredKeySizeInBytes;

        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public int RequiredKeySizeInBits => _requiredKeySizeInBytes << 3;

        /// <summary>
        /// Gets the wrapped key size, in bits.
        /// </summary>
        public ushort KeyWrappedSizeInBytes => _keyWrappedSizeInBytes;

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/>.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm => _signatureAlgorithm;

        /// <summary>
        /// Gets the name of the encryption algorithm.
        /// </summary>
        public string Name => Utf8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => _utf8Name;

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptionAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="requiredKeySizeInBytes"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="requiredKeyWrappedSizeInBytes"></param>
        /// <param name="category"></param>
        public EncryptionAlgorithm(sbyte id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm? hashAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionType category)
        {
            _id = id;
            _utf8Name = Utf8.GetBytes(name);
            _requiredKeySizeInBytes = requiredKeySizeInBytes;
            _signatureAlgorithm = hashAlgorithm;
            _keyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            _category = category;
        }

        /// <summary>
        /// Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            var algorithms = _algorithms;
            for (int i = 0; i < algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(algorithms[i]._utf8Name))
                {
                    algorithm = algorithms[i];
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            if (value.Length == 13)
            {
                ref byte refValue = ref MemoryMarshal.GetReference(value);
                ulong endValue = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref refValue, 5));
                switch (Unsafe.ReadUnaligned<ulong>(ref refValue))
                {
                    case 3261523411619426625u when endValue == 3906083585088373570u:
                        algorithm = Aes128CbcHmacSha256;
                        return true;
                    case 3261523411519222081u when endValue == 3762813921454277442u:
                        algorithm = Aes192CbcHmacSha384;
                        return true;
                    case 3261523411586069057u when endValue == 3616730607564702530u:
                        algorithm = Aes256CbcHmacSha512;
                        return true;
                }
            }
            else if (value.Length == 7)
            {
                switch (Unsafe.ReadUnaligned<ulong>(ref MemoryMarshal.GetReference(value)) & 0x00ffffffffffffffu)
                {
                    case 21747546371273025u:
                        algorithm = Aes128Gcm;
                        return true;
                    case 21747546271068481u:
                        algorithm = Aes192Gcm;
                        return true;
                    case 21747546337915457u:
                        algorithm = Aes256Gcm;
                        return true;
                }
            }

            algorithm = null;
            return false;
        }


        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="EncryptionAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            if (obj is EncryptionAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> objects have the same value.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(EncryptionAlgorithm? other)
        {
            if (other is null)
            {
                return false;
            }

            return _id == other._id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="EncryptionAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator ==(EncryptionAlgorithm? x, EncryptionAlgorithm? y)
        {
            if (y is null)
            {
                return x is null;
            }

            if (x is null)
            {
                return false;
            }

            return x._id == y._id;
        }

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator !=(EncryptionAlgorithm? x, EncryptionAlgorithm? y)
        {
            return !(x == y);
        }

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator string?(EncryptionAlgorithm? value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[]?(EncryptionAlgorithm? value)
        {
            if (value is null)
            {
                return null;
            }

            return value._utf8Name;
        }

        /// <summary>
        /// Cast the array of <see cref="byte"/>s into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm?(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(Utf8.GetString(value));
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm?(string? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(Utf8.GetBytes(value), out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Computes a unique key for the combinaison of the <see cref="EncryptionAlgorithm"/> and the <see cref="KeyManagementAlgorithm"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public int ComputeKey(KeyManagementAlgorithm algorithm)
        {
            return (_id << 8) | (byte)algorithm.Id;
        }
    }
}
