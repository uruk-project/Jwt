// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines key management algorithm.
    /// </summary>
    public class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>, IAlgorithm
    {
        public static readonly KeyManagementAlgorithm Empty = new KeyManagementAlgorithm(0, string.Empty, AlgorithmCategory.None, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, "dir", AlgorithmCategory.Symmetric, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: 11, "A128KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: 12, "A192KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: 13, "A256KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, "A128GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, "A192GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, "A256GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: 31, "RSA1_5", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: 32, "RSA-OAEP", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: 33, "RSA-OAEP-256", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep384 = new KeyManagementAlgorithm(id: 34, "RSA-OAEP-384", AlgorithmCategory.Rsa);
        public static readonly KeyManagementAlgorithm RsaOaep512 = new KeyManagementAlgorithm(id: 35, "RSA-OAEP-512", AlgorithmCategory.Rsa);

        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: 41, "ECDH-ES", AlgorithmCategory.EllipticCurve, produceEncryptedKey: false);

        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(id: 51, "ECDH-ES+A128KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes128KW);
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(id: 52, "ECDH-ES+A192KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes192KW);
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(id: 53, "ECDH-ES+A256KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes256KW);

        public sbyte Id { get; }

        public ushort RequiredKeySizeInBits { get; }

        public AlgorithmCategory Category { get; }

        public KeyManagementAlgorithm WrappedAlgorithm { get; }

        public string Name { get; }

        public bool ProduceEncryptedKey { get; }

        public static Dictionary<string, KeyManagementAlgorithm> Algorithms { get; } = new Dictionary<string, KeyManagementAlgorithm>
        {
            { EcdhEsAes128KW.Name, EcdhEsAes128KW },
            { EcdhEsAes192KW.Name, EcdhEsAes192KW },
            { EcdhEsAes256KW.Name, EcdhEsAes256KW },
            { EcdhEs.Name, EcdhEs },
            { Aes128KW.Name, Aes128KW },
            { Aes192KW.Name, Aes192KW },
            { Aes256KW.Name, Aes256KW },
            { Aes128GcmKW.Name, Aes128GcmKW },
            { Aes192GcmKW.Name, Aes192GcmKW },
            { Aes256GcmKW.Name, Aes256GcmKW },
            { Direct.Name, Direct },
            { RsaOaep.Name, RsaOaep},
            { RsaOaep256.Name, RsaOaep256},
            { RsaOaep384.Name, RsaOaep384},
            { RsaOaep512.Name, RsaOaep512},
            { RsaPkcs1.Name, RsaPkcs1 },
            { Empty.Name, Empty }
        };

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType)
            : this(id, name, keyType, 0, null, true)
        {
        }

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm)
                : this(id, name, keyType, 0, wrappedAlgorithm, true)
        {
        }

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
            : this(id, name, keyType, requiredKeySizeInBits, null, true)
        {
        }

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
            : this(id, name, keyType, 0, null, produceEncryptedKey)
        {
        }

        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, KeyManagementAlgorithm wrappedAlgorithm, bool produceEncryptedKey)
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

        public override string ToString()
        {
            return Name;
        }
    }
}
