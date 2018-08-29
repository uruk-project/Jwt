using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public readonly struct SignatureAlgorithm : IEquatable<SignatureAlgorithm>
    {
        public static readonly SignatureAlgorithm Empty = default;

        // signature algorithms
        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(id: -1, SignatureAlgorithms.None, AlgorithmCategory.None, requiredKeySizeInBits: 0, new HashAlgorithmName());

        public static readonly SignatureAlgorithm HmacSha256 = new SignatureAlgorithm(id: 11, SignatureAlgorithms.HmacSha256, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm HmacSha384 = new SignatureAlgorithm(id: 12, SignatureAlgorithms.HmacSha384, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm HmacSha512 = new SignatureAlgorithm(id: 13, SignatureAlgorithms.HmacSha512, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSha256 = new SignatureAlgorithm(id: 21, SignatureAlgorithms.RsaSha256, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSha384 = new SignatureAlgorithm(id: 22, SignatureAlgorithms.RsaSha384, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSha512 = new SignatureAlgorithm(id: 23, SignatureAlgorithms.RsaSha512, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm EcdsaSha256 = new SignatureAlgorithm(id: 31, SignatureAlgorithms.EcdsaSha256, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm EcdsaSha384 = new SignatureAlgorithm(id: 32, SignatureAlgorithms.EcdsaSha384, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 384, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm EcdsaSha512 = new SignatureAlgorithm(id: 33, SignatureAlgorithms.EcdsaSha512, AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 521, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSsaPssSha256 = new SignatureAlgorithm(id: 40, SignatureAlgorithms.RsaSsaPssSha256, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSsaPssSha384 = new SignatureAlgorithm(id: 41, SignatureAlgorithms.RsaSsaPssSha384, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSsaPssSha512 = new SignatureAlgorithm(id: 42, SignatureAlgorithms.RsaSsaPssSha512, AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA512);

        public static readonly IDictionary<string, SignatureAlgorithm> AdditionalAlgorithms = new Dictionary<string, SignatureAlgorithm>();

        private readonly long _id;

        public readonly string Name;
        public readonly AlgorithmCategory Category;
        public readonly int RequiredKeySizeInBits;
        public readonly HashAlgorithmName HashAlgorithm;

        private SignatureAlgorithm(long id, string name, AlgorithmCategory keyType, int requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            _id = id;
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
            return _id == other._id;
        }

        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        public static bool operator ==(in SignatureAlgorithm x, SignatureAlgorithm y)
        {
            return x._id == y._id;
        }

        public static bool operator !=(in SignatureAlgorithm x, in SignatureAlgorithm y)
        {
            return x._id != y._id;
        }

        public static implicit operator string(in SignatureAlgorithm value)
        {
            return value.Name;
        }

        public static implicit operator SignatureAlgorithm(string value)
        {
            switch (value)
            {
                case SignatureAlgorithms.EcdsaSha256:
                    return EcdsaSha256;
                case SignatureAlgorithms.EcdsaSha384:
                    return EcdsaSha384;
                case SignatureAlgorithms.EcdsaSha512:
                    return EcdsaSha512;

                case SignatureAlgorithms.HmacSha256:
                    return HmacSha256;
                case SignatureAlgorithms.HmacSha384:
                    return HmacSha384;
                case SignatureAlgorithms.HmacSha512:
                    return HmacSha512;

                case SignatureAlgorithms.RsaSha256:
                    return RsaSha256;
                case SignatureAlgorithms.RsaSha384:
                    return RsaSha384;
                case SignatureAlgorithms.RsaSha512:
                    return RsaSha512;

                case SignatureAlgorithms.RsaSsaPssSha256:
                    return RsaSsaPssSha256;
                case SignatureAlgorithms.RsaSsaPssSha384:
                    return RsaSsaPssSha384;
                case SignatureAlgorithms.RsaSsaPssSha512:
                    return RsaSsaPssSha512;

                case SignatureAlgorithms.None:
                    return None;

                case null:
                case "":
                    return Empty;
            }

            if (AdditionalAlgorithms.TryGetValue(value, out var algorithm))
            {
                return algorithm;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, value));
        }


        public static implicit operator long(in SignatureAlgorithm value)
        {
            return value._id;
        }

        public override string ToString()
        {
            return Name;
        }
    }
}
