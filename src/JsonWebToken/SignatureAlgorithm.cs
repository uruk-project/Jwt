using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class SignatureAlgorithm : IEquatable<SignatureAlgorithm>
    {
        public static readonly SignatureAlgorithm Empty = new SignatureAlgorithm(0, string.Empty, AlgorithmCategory.None, 0, new HashAlgorithmName());

        // signature algorithms
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

        public static readonly IDictionary<string, SignatureAlgorithm> AdditionalAlgorithms = new Dictionary<string, SignatureAlgorithm>();

        public readonly sbyte Id;
        public readonly AlgorithmCategory Category;
        public readonly ushort RequiredKeySizeInBits;
        public readonly HashAlgorithmName HashAlgorithm;

        public readonly string Name;

        private SignatureAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            Id = id;
            Name = name;
            Category = keyType;
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
            switch (value)
            {
                case "ES256":
                    return EcdsaSha256;
                case "ES384":
                    return EcdsaSha384;
                case "ES512":
                    return EcdsaSha512;

                case "HS256":
                    return HmacSha256;
                case "HS384":
                    return HmacSha384;
                case "HS512":
                    return HmacSha512;

                case "RS256":
                    return RsaSha256;
                case "RS384":
                    return RsaSha384;
                case "RS512":
                    return RsaSha512;

                case "PS256":
                    return RsaSsaPssSha256;
                case "PS384":
                    return RsaSsaPssSha384;
                case "PS512":
                    return RsaSsaPssSha512;

                case "none":
                    return None;

                case null:
                case "":
                    return Empty;
            }

            if (!AdditionalAlgorithms.TryGetValue(value, out var algorithm))
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
