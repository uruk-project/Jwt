using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public readonly struct KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>
    {
        public static readonly KeyManagementAlgorithm Empty = default;

        // Key wrapping algoritmhs
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, KeyManagementAlgorithms.Direct, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 0, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: 11, KeyManagementAlgorithms.Aes128KW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: 12, KeyManagementAlgorithms.Aes192KW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: 13, KeyManagementAlgorithms.Aes256KW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, KeyManagementAlgorithms.Aes128GcmKW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, KeyManagementAlgorithms.Aes192GcmKW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, KeyManagementAlgorithms.Aes256GcmKW, AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: 31, KeyManagementAlgorithms.RsaPkcs1, AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: 32, KeyManagementAlgorithms.RsaOaep, AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: 33, KeyManagementAlgorithms.RsaOaep256, AlgorithmCategory.Rsa);

        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: 41, KeyManagementAlgorithms.EcdhEs, AlgorithmCategory.EllipticCurve, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(id: 51, KeyManagementAlgorithms.EcdhEsAes128KW, AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes128KW.Name);
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(id: 52, KeyManagementAlgorithms.EcdhEsAes192KW, AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes192KW.Name);
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(id: 53, KeyManagementAlgorithms.EcdhEsAes256KW, AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes256KW.Name);

        public static readonly IDictionary<string, KeyManagementAlgorithm> AdditionalAlgorithms = new Dictionary<string, KeyManagementAlgorithm>();

        private readonly long _id;

        public readonly string Name;
        public readonly AlgorithmCategory Category;
        public readonly int RequiredKeySizeInBits;
        public readonly HashAlgorithmName HashAlgorithm;
        public readonly string WrappedAlgorithm;
        public readonly bool ProduceEncryptedKey;

        private KeyManagementAlgorithm(long id, string name, AlgorithmCategory keyType, int requiredKeySizeInBits = 0, string wrappedAlgorithm = null, bool produceEncryptedKey = true)
        {
            _id = id;
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
            return _id == other._id;
        }

        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        public static bool operator ==(in KeyManagementAlgorithm x, in KeyManagementAlgorithm y)
        {
            return x._id == y._id;
        }

        public static bool operator !=(in KeyManagementAlgorithm x, in KeyManagementAlgorithm y)
        {
            return x._id != y._id;
        }

        public static explicit operator string(in KeyManagementAlgorithm value)
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
