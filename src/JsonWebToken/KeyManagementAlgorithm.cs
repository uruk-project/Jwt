using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public readonly struct KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>
    {
        public static readonly KeyManagementAlgorithm Empty = default;

        // Key wrapping algoritmhs
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(1, KeyManagementAlgorithms.Direct, KeyTypes.Octet, 0);

        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(2, KeyManagementAlgorithms.Aes128KW, KeyTypes.Octet, 128);
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(3, KeyManagementAlgorithms.Aes192KW, KeyTypes.Octet, 192);
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(4, KeyManagementAlgorithms.Aes256KW, KeyTypes.Octet, 256);

        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(5, KeyManagementAlgorithms.RsaPkcs1, KeyTypes.RSA);
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(6, KeyManagementAlgorithms.RsaOaep, KeyTypes.RSA);
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(7, KeyManagementAlgorithms.RsaOaep256, KeyTypes.RSA);

        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(8, KeyManagementAlgorithms.EcdhEs, KeyTypes.EllipticCurve);

        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(9, KeyManagementAlgorithms.EcdhEsAes128KW, KeyTypes.EllipticCurve, wrappedAlgorithm: Aes128KW.Name);
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(10, KeyManagementAlgorithms.EcdhEsAes192KW, KeyTypes.EllipticCurve, wrappedAlgorithm: Aes192KW.Name);
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(11, KeyManagementAlgorithms.EcdhEsAes256KW, KeyTypes.EllipticCurve, wrappedAlgorithm: Aes256KW.Name);

        public static readonly IDictionary<string, KeyManagementAlgorithm> AdditionalAlgorithms = new Dictionary<string, KeyManagementAlgorithm>();

        public readonly string Name;
        public readonly long Id;

        public readonly string KeyType;
        public readonly int RequiredKeySizeInBits;
        public readonly HashAlgorithmName HashAlgorithm;
        public readonly string WrappedAlgorithm;

        private KeyManagementAlgorithm(long id, string name, string keyType, int requiredKeySizeInBits = 0, string wrappedAlgorithm = null)
        {
            Name = name;
            Id = id;
            KeyType = keyType;
            RequiredKeySizeInBits = requiredKeySizeInBits;
            WrappedAlgorithm = wrappedAlgorithm;
        }

        public override bool Equals(object obj)
        {
            if (obj is KeyManagementAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        public bool Equals(KeyManagementAlgorithm other)
        {
            return Id == other.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static bool operator ==(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
        {
            return x.Id == y.Id;
        }

        public static bool operator !=(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
        {
            return x.Id != y.Id;
        }

        public static explicit operator string(KeyManagementAlgorithm value)
        {
            return value.Name;
        }

        public static explicit operator KeyManagementAlgorithm(string value)
        {
            switch (value)
            {
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                    return EcdhEsAes128KW;
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                    return EcdhEsAes192KW;
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return EcdhEsAes256KW;

                case KeyManagementAlgorithms.EcdhEs:
                    return EcdhEs;

                case KeyManagementAlgorithms.Aes128KW:
                    return Aes128KW;
                case KeyManagementAlgorithms.Aes192KW:
                    return Aes192KW;
                case KeyManagementAlgorithms.Aes256KW:
                    return Aes256KW;

                case KeyManagementAlgorithms.Direct:
                    return Direct;

                case KeyManagementAlgorithms.RsaOaep:
                    return RsaOaep;
                case KeyManagementAlgorithms.RsaOaep256:
                    return RsaOaep;
                case KeyManagementAlgorithms.RsaPkcs1:
                    return RsaPkcs1;

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
