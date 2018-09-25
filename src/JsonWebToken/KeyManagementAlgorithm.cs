using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>
    {
        public static readonly KeyManagementAlgorithm Empty = new KeyManagementAlgorithm(0, string.Empty, AlgorithmCategory.None, 0, null, false);

        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, "dir", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 0, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: 11, "A128KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: 12, "A192KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: 13, "A256KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, "A128GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, "A192GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, "A256GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: 31, "RSA1_5", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: 32, "RSA-OAEP", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: 33, "RSA-OAEP-256", AlgorithmCategory.Rsa);

        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: 41, "ECDH-ES", AlgorithmCategory.EllipticCurve, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(id: 51, "ECDH-ES+A128KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes128KW);
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(id: 52, "ECDH-ES+A192KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes192KW);
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(id: 53, "ECDH-ES+A256KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes256KW);

        public static readonly IDictionary<string, KeyManagementAlgorithm> AdditionalAlgorithms = new Dictionary<string, KeyManagementAlgorithm>();

        public sbyte Id { get; }

        public ushort RequiredKeySizeInBits { get; }

        public AlgorithmCategory Category { get; }

        public KeyManagementAlgorithm WrappedAlgorithm { get; }

        public string Name { get; }

        public bool ProduceEncryptedKey { get; }

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits = 0, KeyManagementAlgorithm wrappedAlgorithm = null, bool produceEncryptedKey = true)
        {
            Id = id;
            Name = name;
            Category = keyType;
            RequiredKeySizeInBits = requiredKeySizeInBits;
            WrappedAlgorithm = wrappedAlgorithm;
            ProduceEncryptedKey = produceEncryptedKey;
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

        public static bool operator ==(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
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

        public static bool operator !=(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
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

        public static implicit operator string(KeyManagementAlgorithm value)
        {
            return value?.Name;
        }

        public static explicit operator KeyManagementAlgorithm(string value)
        {
            switch (value)
            {
                case "ECDH-ES+A128KW":
                    return EcdhEsAes128KW;
                case "ECDH-ES+A192KW":
                    return EcdhEsAes192KW;
                case "ECDH-ES+A256KW":
                    return EcdhEsAes256KW;

                case "ECDH-ES":
                    return EcdhEs;

                case "A128KW":
                    return Aes128KW;
                case "A192KW":
                    return Aes192KW;
                case "A256KW":
                    return Aes256KW;

                case "A128GCMKW":
                    return Aes128GcmKW;
                case "A192GCMKW":
                    return Aes192GcmKW;
                case "A256GCMKW":
                    return Aes256GcmKW;

                case "dir":
                    return Direct;

                case "RSA-OAEP":
                    return RsaOaep;
                case "RSA-OAEP-256":
                    return RsaOaep;
                case "RSA1_5":
                    return RsaPkcs1;

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

        public override string ToString()
        {
            return Name;
        }
    }
}
