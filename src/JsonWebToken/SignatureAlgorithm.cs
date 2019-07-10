// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines signature algorithm.
    /// </summary>
    public sealed class SignatureAlgorithm : IEquatable<SignatureAlgorithm>
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

        private static readonly Dictionary<string, SignatureAlgorithm> _algorithms = new Dictionary<string, SignatureAlgorithm>
        {
            { EcdsaSha256.Name, EcdsaSha256 },
            { EcdsaSha384.Name, EcdsaSha384 },
            { EcdsaSha512.Name, EcdsaSha512 },
            { HmacSha256.Name, HmacSha256 },
            { HmacSha384.Name, HmacSha384 },
            { HmacSha512.Name, HmacSha512 },
            { RsaSha256.Name, RsaSha256 },
            { RsaSha384.Name, RsaSha384 },
            { RsaSha512.Name, RsaSha512 },
            { RsaSsaPssSha256.Name, RsaSsaPssSha256},
            { RsaSsaPssSha384.Name, RsaSsaPssSha384},
            { RsaSsaPssSha512.Name, RsaSsaPssSha512},
            { None.Name, None }
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
        /// Gets the <see cref="SignatureAlgorithm"/> list. 
        /// </summary>
        public static Dictionary<string, SignatureAlgorithm> Algorithms => _algorithms;

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
        public override bool Equals(object obj)
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
        public bool Equals(SignatureAlgorithm other)
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
        public static bool operator ==(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            if (x is null && y is null)
            {
                return true;
            }

            if (x is null)
            {
                goto NotEqual;
            }

            if (y is null)
            {
                goto NotEqual;
            }

            return x._id == y._id;
        NotEqual:
            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="SignatureAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            if (x is null && y is null)
            {
                return false;
            }

            if (x is null)
            {
                goto NotEqual;
            }

            if (y is null)
            {
                goto NotEqual;
            }

            return x._id != y._id;
        NotEqual:
            return true;
        }

        /// <summary>
        /// Cast the <see cref="SignatureAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator string(SignatureAlgorithm value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm(string value)
        {
            if (value == null)
            {
                return null;
            }

            if (!Algorithms.TryGetValue(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm(byte[] value)
        {
            return (SignatureAlgorithm)(ReadOnlySpan<byte>)value;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public unsafe static bool TryParse(ReadOnlySpan<byte> value, out SignatureAlgorithm algorithm)
        {
            if (value.IsEmpty)
            {
                algorithm = null;
                return true;
            }

            fixed (byte* pValue = value)
            {
                if (value.Length == 5)
                {
                    switch (*(int*)(pValue + 1))
                    {
                        case 909455955 /* S256 */:
                            switch (value[0])
                            {
                                case (byte)'H':
                                    algorithm = HmacSha256;
                                    return true;
                                case (byte)'R':
                                    algorithm = RsaSha256;
                                    return true;
                                case (byte)'E':
                                    algorithm = EcdsaSha256;
                                    return true;
                                case (byte)'P':
                                    algorithm = RsaSsaPssSha256;
                                    return true;
                            }
                            break;
                        case 876098387 /* S384 */:
                            switch (value[0])
                            {
                                case (byte)'H':
                                    algorithm = HmacSha384;
                                    return true;
                                case (byte)'R':
                                    algorithm = RsaSha384;
                                    return true;
                                case (byte)'E':
                                    algorithm = EcdsaSha384;
                                    return true;
                                case (byte)'P':
                                    algorithm = RsaSsaPssSha384;
                                    return true;
                            }
                            break;
                        case 842085715 /* S512 */:
                            switch (value[0])
                            {
                                case (byte)'H':
                                    algorithm = HmacSha512;
                                    return true;
                                case (byte)'R':
                                    algorithm = RsaSha512;
                                    return true;
                                case (byte)'E':
                                    algorithm = EcdsaSha512;
                                    return true;
                                case (byte)'P':
                                    algorithm = RsaSsaPssSha512;
                                    return true;
                            }
                            break;
                    }
                }
                else if (value.Length == 4 && *(int*)pValue == 1701736302/* none */)
                {
                    algorithm = None;
                    return true;
                }

                algorithm = null;
                return false;
            }
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public unsafe static explicit operator SignatureAlgorithm(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(Encoding.UTF8.GetString(value.ToArray()));
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="SignatureAlgorithm"/> into its <see cref="long"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator long(SignatureAlgorithm value)
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
        public static explicit operator byte[](SignatureAlgorithm value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
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
