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
        /// <summary>
        /// Empty.
        /// </summary>
        public static readonly KeyManagementAlgorithm Empty = new KeyManagementAlgorithm(0, string.Empty, AlgorithmCategory.None, produceEncryptedKey: false);

        /// <summary>
        /// 'dir'
        /// </summary>
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, "dir", AlgorithmCategory.Symmetric, produceEncryptedKey: false);

        /// <summary>
        /// 'A128KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: 11, "A128KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: 12, "A192KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: 13, "A256KW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, "A128GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, "A192GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, "A256GCMKW", AlgorithmCategory.Symmetric, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: 31, "RSA1_5", AlgorithmCategory.Rsa);

        /// <summary>
        /// 'RSA-OAEP'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: 32, "RSA-OAEP", AlgorithmCategory.Rsa);

        /// <summary>
        /// 'RSA-OAEP-128'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: 33, "RSA-OAEP-256", AlgorithmCategory.Rsa);

        /// <summary>
        /// 'RSA-OAEP-192'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep384 = new KeyManagementAlgorithm(id: 34, "RSA-OAEP-384", AlgorithmCategory.Rsa);

        /// <summary>
        /// 'RSA-OAEP-256'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep512 = new KeyManagementAlgorithm(id: 35, "RSA-OAEP-512", AlgorithmCategory.Rsa);

        /// <summary>
        /// 'ECDH-ES'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: 41, "ECDH-ES", AlgorithmCategory.EllipticCurve, produceEncryptedKey: false);

        /// <summary>
        /// 'ECDH-ES+A128KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(id: 51, "ECDH-ES+A128KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes128KW);

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(id: 52, "ECDH-ES+A192KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes192KW);

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(id: 53, "ECDH-ES+A256KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes256KW);
  
        // TODO : Verify the pertinence
        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id { get; }
    
        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public ushort RequiredKeySizeInBits { get; }

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public AlgorithmCategory Category { get; }

        /// <summary>
        /// Gets the wrapped algo
        /// </summary>
        public KeyManagementAlgorithm WrappedAlgorithm { get; }
    
        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets whether the algorithm produce an encryption key.
        /// </summary>
        public bool ProduceEncryptionKey { get; }

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/> list; 
        /// </summary>
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

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType)
            : this(id, name, keyType, 0, null, true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="wrappedAlgorithm"></param>
        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm)
                : this(id, name, keyType, 0, wrappedAlgorithm, true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="requiredKeySizeInBits"></param>
        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
            : this(id, name, keyType, requiredKeySizeInBits, null, true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="produceEncryptedKey"></param>
        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
            : this(id, name, keyType, 0, null, produceEncryptedKey)
        {
        }
    
        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="requiredKeySizeInBits"></param>
        /// <param name="wrappedAlgorithm"></param>
        /// <param name="produceEncryptedKey"></param>
        public KeyManagementAlgorithm(sbyte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, KeyManagementAlgorithm wrappedAlgorithm, bool produceEncryptedKey)
        {
            Id = id;
            Name = name;
            Category = keyType;
            RequiredKeySizeInBits = requiredKeySizeInBits;
            WrappedAlgorithm = wrappedAlgorithm;
            ProduceEncryptionKey = produceEncryptedKey;
        }

        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="KeyManagementAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is KeyManagementAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> objects have the same value.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(KeyManagementAlgorithm other)
        {
            if (other is null)
            {
                return false;
            }

            return Id == other.Id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="KeyManagementAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator string(KeyManagementAlgorithm value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
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

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }
    }
}
