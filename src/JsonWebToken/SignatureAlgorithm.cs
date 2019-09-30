// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Defines signature algorithm.
    /// </summary>
    public sealed class SignatureAlgorithm : IEquatable<SignatureAlgorithm>, IAlgorithm
    {
        /// <summary>
        /// 'none'
        /// </summary>
        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(id: JsonWebToken.Algorithms.None, "none", AlgorithmCategory.None, requiredKeySizeInBits: 0, new HashAlgorithmName());

        /// <summary>
        /// 'HS256'
        /// </summary>
        public static readonly SignatureAlgorithm HmacSha256 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.HmacSha256, "HS256", AlgorithmCategory.Hmac, requiredKeySizeInBits: 128/*?*/, HashAlgorithmName.SHA256);

        /// <summary>
        /// 'HS384'
        /// </summary>
        public static readonly SignatureAlgorithm HmacSha384 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.HmacSha384, "HS384", AlgorithmCategory.Hmac, requiredKeySizeInBits: 192/*?*/, HashAlgorithmName.SHA384);

        /// <summary>
        /// 'HS512'
        /// </summary>
        public static readonly SignatureAlgorithm HmacSha512 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.HmacSha512, "HS512", AlgorithmCategory.Hmac, requiredKeySizeInBits: 256/*?*/, HashAlgorithmName.SHA512);

        /// <summary>
        /// 'RS256'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSha256 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSha256, "RS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA256);

        /// <summary>
        /// 'RS384'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSha384 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSha384, "RS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA384);

        /// <summary>
        /// 'RS512'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSha512 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSha512, "RS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA512);

        /// <summary>
        /// 'ES256'
        /// </summary>
        public static readonly SignatureAlgorithm EcdsaSha256 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.EcdsaSha256, "ES256", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);

        /// <summary>
        /// 'ES384'
        /// </summary>
        public static readonly SignatureAlgorithm EcdsaSha384 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.EcdsaSha384, "ES384", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 384, HashAlgorithmName.SHA384);

        /// <summary>
        /// 'ES512'
        /// </summary>
        public static readonly SignatureAlgorithm EcdsaSha512 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.EcdsaSha512, "ES512", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 521, HashAlgorithmName.SHA512);

        /// <summary>
        /// 'PS256'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSsaPssSha256 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSsaPssSha256, "PS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA256);

        /// <summary>
        /// 'PS384'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSsaPssSha384 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSsaPssSha384, "PS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA384);

        /// <summary>
        /// 'PS512'
        /// </summary>
        public static readonly SignatureAlgorithm RsaSsaPssSha512 = new SignatureAlgorithm(id: JsonWebToken.Algorithms.RsaSsaPssSha512, "PS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA512);

        private readonly int _id;
        private readonly byte[] _utf8Name;
        private readonly AlgorithmCategory _category;
        private readonly ushort _requiredKeySizeInBits;
        private readonly HashAlgorithmName _hashAlgorithm;

        private static readonly SignatureAlgorithm[] _algorithms = new[]
        {
            HmacSha256,
            EcdsaSha256,
            RsaSha256,
            RsaSsaPssSha256,
            HmacSha512,
            EcdsaSha512,
            RsaSha512,
            RsaSsaPssSha512,
            HmacSha384,
            EcdsaSha384,
            RsaSha384,
            RsaSsaPssSha384,
            None
        };

        // TODO : Verify the pertinence
        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public int Id => _id;

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public string Name => Encoding.UTF8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => _utf8Name;

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public AlgorithmCategory Category => _category;

        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public ushort RequiredKeySizeInBits => _requiredKeySizeInBits;

        /// <summary>
        /// Gets the hash algorithm. 
        /// </summary>
        public HashAlgorithmName HashAlgorithm => _hashAlgorithm;

        /// <summary>
        /// Initializes a new instance of <see cref="SignatureAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="category"></param>
        /// <param name="requiredKeySizeInBits"></param>
        /// <param name="hashAlgorithm"></param>
        public SignatureAlgorithm(int id, string name, AlgorithmCategory category, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            _id = id;
            _utf8Name = Encoding.UTF8.GetBytes(name);
            _category = category;
            _requiredKeySizeInBits = requiredKeySizeInBits;
            _hashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="SignatureAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            if (obj is SignatureAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="SignatureAlgorithm"/> objects have the same value.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SignatureAlgorithm? other)
        {
            if (other is null)
            {
                return false;
            }

            return _id == other._id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="SignatureAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="SignatureAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator ==(SignatureAlgorithm? x, SignatureAlgorithm? y)
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
        /// Determines whether two specified <see cref="SignatureAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(SignatureAlgorithm? x, SignatureAlgorithm? y)
        {
            return !(x == y);
        }

        /// <summary>
        /// Cast the <see cref="SignatureAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator string?(SignatureAlgorithm? value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm?(string? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(Encoding.UTF8.GetBytes(value), out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm?(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(Encoding.UTF8.GetString(value));
            }

            return algorithm;
        }

        /// <summary>
        /// Reads the current value of the <paramref name="reader"/> and converts into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            for (int i = 0; i < _algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(_algorithms[i]._utf8Name))
                {
                    algorithm = _algorithms[i];
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Parses the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            if (value.Length == 5)
            {
                ref byte valueRef = ref MemoryMarshal.GetReference(value);
                var first = valueRef;
                var refvalue = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref valueRef, 1));
                switch (refvalue)
                {
                    case 909455955u when first == (byte)'H':
                        algorithm = HmacSha256;
                        return true;
                    case 909455955u when first == (byte)'R':
                        algorithm = RsaSha256;
                        return true;
                    case 909455955u when first == (byte)'E':
                        algorithm = EcdsaSha256;
                        return true;
                    case 909455955u when first == (byte)'P':
                        algorithm = RsaSsaPssSha256;
                        return true;
                    case 876098387u when first == (byte)'H':
                        algorithm = HmacSha384;
                        return true;
                    case 876098387u when first == (byte)'R':
                        algorithm = RsaSha384;
                        return true;
                    case 876098387u when first == (byte)'E':
                        algorithm = EcdsaSha384;
                        return true;
                    case 876098387u when first == (byte)'P':
                        algorithm = RsaSsaPssSha384;
                        return true;
                    case 842085715u when first == (byte)'H':
                        algorithm = HmacSha512;
                        return true;
                    case 842085715u when first == (byte)'R':
                        algorithm = RsaSha512;
                        return true;
                    case 842085715u when first == (byte)'E':
                        algorithm = EcdsaSha512;
                        return true;
                    case 842085715u when first == (byte)'P':
                        algorithm = RsaSsaPssSha512;
                        return true;
                }
            }
            else if (value.Length == 4 && Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(value)) == 1701736302u /* none */)
            {
                algorithm = None;
                return true;
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ref Utf8JsonReader reader, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            var value = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
            if (TryParse(value, out algorithm))
            {
                return true;
            }

            return TryParseSlow(ref reader, out algorithm);
        }

        /// <summary>
        /// Cast the <see cref="SignatureAlgorithm"/> into its <see cref="long"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator long(SignatureAlgorithm? value)
        {
            if (value is null)
            {
                return 0;
            }

            return value._id;
        }

        /// <summary>
        /// Cast the <see cref="SignatureAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[]?(SignatureAlgorithm? value)
        {
            if (value is null)
            {
                return null;
            }

            return value.Utf8Name;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }
    }
}
