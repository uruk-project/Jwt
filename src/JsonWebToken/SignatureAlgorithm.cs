// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Defines signature algorithm.
    /// </summary>
    public sealed class SignatureAlgorithm : IEquatable<SignatureAlgorithm>, IAlgorithm
    {
        public static readonly SignatureAlgorithm Empty = new SignatureAlgorithm(0, string.Empty, AlgorithmCategory.None, 0, new HashAlgorithmName());

        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(id: -1, "none", AlgorithmCategory.None, requiredKeySizeInBits: 0, new HashAlgorithmName());

        public static readonly SignatureAlgorithm HmacSha256 = new SignatureAlgorithm(id: 11, "HS256", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm HmacSha384 = new SignatureAlgorithm(id: 12, "HS384", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm HmacSha512 = new SignatureAlgorithm(id: 13, "HS512", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSha256 = new SignatureAlgorithm(id: 21, "RS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSha384 = new SignatureAlgorithm(id: 22, "RS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSha512 = new SignatureAlgorithm(id: 23, "RS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm EcdsaSha256 = new SignatureAlgorithm(id: 31, "ES256", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm EcdsaSha384 = new SignatureAlgorithm(id: 32, "ES384", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 384, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm EcdsaSha512 = new SignatureAlgorithm(id: 33, "ES512", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 521, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSsaPssSha256 = new SignatureAlgorithm(id: 40, "PS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSsaPssSha384 = new SignatureAlgorithm(id: 41, "PS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSsaPssSha512 = new SignatureAlgorithm(id: 42, "PS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA512);

        public sbyte Id { get; }

        public string Name { get; }

        public AlgorithmCategory Category { get; }

        public ushort RequiredKeySizeInBits { get; }

        public HashAlgorithmName HashAlgorithm { get; }

        public static Dictionary<string, SignatureAlgorithm> Algorithms { get; } = new Dictionary<string, SignatureAlgorithm>
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
            { None.Name, None },
            { Empty.Name, Empty}
        };

        public SignatureAlgorithm(sbyte id, string name, AlgorithmCategory category, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            Id = id;
            Name = name;
            Category = category;
            RequiredKeySizeInBits = requiredKeySizeInBits;
            HashAlgorithm = hashAlgorithm;
        }

        public override bool Equals(object obj)
        {
            if (obj is SignatureAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        public bool Equals(SignatureAlgorithm other)
        {
            if (other is null)
            {
                return false;
            }

            return Id == other.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static bool operator ==(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            if (x is null && y is null)
            {
                return true;
            }

            if (x is null)
            {
                return false;
            }

            if (y is null)
            {
                return false;
            }

            return x.Id == y.Id;
        }

        public static bool operator !=(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            if (x is null && y is null)
            {
                return false;
            }

            if (x is null)
            {
                return true;
            }

            if (y is null)
            {
                return true;
            }

            return x.Id != y.Id;
        }

        public static implicit operator string(SignatureAlgorithm value)
        {
            return value?.Name;
        }

        public static implicit operator SignatureAlgorithm(string value)
        {
            if (value == null)
            {
                return Empty;
            }

            if (!Algorithms.TryGetValue(value, out var algorithm))
            {
                Errors.ThrowNotSupportedAlgorithm(value);
            }

            return algorithm;
        }

        public static implicit operator long(SignatureAlgorithm value)
        {
            return value.Id;
        }

        public override string ToString()
        {
            return Name;
        }
    }
}
