// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines encryption algorithm.
    /// </summary>
    public class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>, IAlgorithm
    {
        public static readonly EncryptionAlgorithm Empty = new EncryptionAlgorithm(0, string.Empty, 0, SignatureAlgorithm.Empty, 0, EncryptionType.None);

        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(id: 11, "A128CBC-HS256", requiredKeySizeInBytes: 32, SignatureAlgorithm.HmacSha256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(id: 12, "A192CBC-HS384", requiredKeySizeInBytes: 48, SignatureAlgorithm.HmacSha384, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesHmac);
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(id: 13, "A256CBC-HS512", requiredKeySizeInBytes: 64, SignatureAlgorithm.HmacSha512, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesHmac);

        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(id: 21, "A128GCM", requiredKeySizeInBytes: 16, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesGcm);
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(id: 22, "A192GCM", requiredKeySizeInBytes: 24, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesGcm);
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(id: 23, "A256GCM", requiredKeySizeInBytes: 32, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesGcm);

        public sbyte Id { get; }

        public EncryptionType Category { get; }

        public ushort RequiredKeySizeInBytes { get; }

        public ushort RequiredKeyWrappedSizeInBytes { get; }

        public SignatureAlgorithm SignatureAlgorithm { get; }

        public string Name { get; }

        public static IDictionary<string, EncryptionAlgorithm> Algorithms { get; } = new Dictionary<string, EncryptionAlgorithm>
        {
            { Aes128CbcHmacSha256.Name, Aes128CbcHmacSha256 },
            { Aes192CbcHmacSha384.Name, Aes192CbcHmacSha384 },
            { Aes256CbcHmacSha512.Name, Aes256CbcHmacSha512 },
            { Aes128Gcm.Name, Aes128Gcm },
            { Aes192Gcm.Name, Aes192Gcm },
            { Aes256Gcm.Name , Aes256Gcm },
            { Empty.Name, Empty }
        };

        public EncryptionAlgorithm(sbyte id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionType category)
        {
            Id = id;
            Name = name;
            RequiredKeySizeInBytes = requiredKeySizeInBytes;
            SignatureAlgorithm = hashAlgorithm;
            RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            Category = category;
        }

        public override bool Equals(object obj)
        {
            if (obj is EncryptionAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        public bool Equals(EncryptionAlgorithm other)
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

        public static bool operator ==(EncryptionAlgorithm x, EncryptionAlgorithm y)
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

        public static bool operator !=(EncryptionAlgorithm x, EncryptionAlgorithm y)
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

        public static implicit operator string(EncryptionAlgorithm value)
        {
            return value?.Name;
        }

        public static explicit operator EncryptionAlgorithm(string value)
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
