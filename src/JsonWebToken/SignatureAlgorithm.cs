using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public readonly struct SignatureAlgorithm : IEquatable<SignatureAlgorithm>
    {
        public static readonly SignatureAlgorithm Empty = default;

        // signature algorithms
        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(-1, SignatureAlgorithms.None, null, 0, new HashAlgorithmName());

        public static readonly SignatureAlgorithm HmacSha256 = new SignatureAlgorithm(1, SignatureAlgorithms.HmacSha256, KeyTypes.Octet, 128/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm HmacSha384 = new SignatureAlgorithm(2, SignatureAlgorithms.HmacSha384, KeyTypes.Octet, 192/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm HmacSha512 = new SignatureAlgorithm(3, SignatureAlgorithms.HmacSha512, KeyTypes.Octet, 256/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSha256 = new SignatureAlgorithm(4, SignatureAlgorithms.RsaSha256, KeyTypes.RSA, 2048/*?*/, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSha384 = new SignatureAlgorithm(5, SignatureAlgorithms.RsaSha384, KeyTypes.RSA, 2048/*?*/, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSha512 = new SignatureAlgorithm(6, SignatureAlgorithms.RsaSha512, KeyTypes.RSA, 2048/*?*/, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm EcdsaSha256 = new SignatureAlgorithm(7, SignatureAlgorithms.EcdsaSha256, KeyTypes.EllipticCurve, 256, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm EcdsaSha384 = new SignatureAlgorithm(8, SignatureAlgorithms.EcdsaSha384, KeyTypes.EllipticCurve, 384, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm EcdsaSha512 = new SignatureAlgorithm(9, SignatureAlgorithms.EcdsaSha512, KeyTypes.EllipticCurve, 521, HashAlgorithmName.SHA512);

        public static readonly SignatureAlgorithm RsaSsaPssSha256 = new SignatureAlgorithm(10, SignatureAlgorithms.RsaSsaPssSha256, KeyTypes.RSA, 2048, HashAlgorithmName.SHA256);
        public static readonly SignatureAlgorithm RsaSsaPssSha384 = new SignatureAlgorithm(11, SignatureAlgorithms.RsaSsaPssSha384, KeyTypes.RSA, 2048, HashAlgorithmName.SHA384);
        public static readonly SignatureAlgorithm RsaSsaPssSha512 = new SignatureAlgorithm(12, SignatureAlgorithms.RsaSsaPssSha512, KeyTypes.RSA, 2048, HashAlgorithmName.SHA512);

        public static readonly IDictionary<string, SignatureAlgorithm> AdditionalAlgorithms = new Dictionary<string, SignatureAlgorithm>();

        public readonly string Name;
        public readonly long Id;

        public readonly string KeyType;
        public readonly int RequiredKeySizeInBits;
        public readonly HashAlgorithmName HashAlgorithm;

        private SignatureAlgorithm(long id, string name, string keyType, int requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            Name = name;
            Id = id;
            KeyType = keyType;
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
            return Id == other.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static bool operator ==(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            return x.Id == y.Id;
        }

        public static bool operator !=(SignatureAlgorithm x, SignatureAlgorithm y)
        {
            return x.Id != y.Id;
        }

        public static implicit operator string(SignatureAlgorithm value)
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

        public override string ToString()
        {
            return Name;
        }
    }
}
