using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>
    {
        public static readonly EncryptionAlgorithm Empty = new EncryptionAlgorithm(0, string.Empty, 0, SignatureAlgorithm.Empty, 0, EncryptionTypes.None);

        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(id: 11, "A128CBC-HS256", requiredKeySizeInBytes: 32, SignatureAlgorithm.HmacSha256, requiredKeyWrappedSizeInBytes: 40, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(id: 12, "A192CBC-HS384", requiredKeySizeInBytes: 48, SignatureAlgorithm.HmacSha384, requiredKeyWrappedSizeInBytes: 56, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(id: 13, "A256CBC-HS512", requiredKeySizeInBytes: 64, SignatureAlgorithm.HmacSha512, requiredKeyWrappedSizeInBytes: 72, EncryptionTypes.AesHmac);

        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(id: 21, "A128GCM", requiredKeySizeInBytes: 16, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 40, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(id: 22, "A192GCM", requiredKeySizeInBytes: 24, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 56, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(id: 23, "A256GCM", requiredKeySizeInBytes: 32, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 72, EncryptionTypes.AesGcm);

        public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

        public readonly sbyte Id;
        public readonly EncryptionTypes Category;

        public readonly ushort RequiredKeySizeInBytes;
        public readonly ushort RequiredKeyWrappedSizeInBytes;
        public readonly SignatureAlgorithm SignatureAlgorithm;
        public readonly string Name;

        private EncryptionAlgorithm(sbyte id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionTypes encryptionType)
        {
            Id = id;
            Name = name;
            RequiredKeySizeInBytes = requiredKeySizeInBytes;
            SignatureAlgorithm = hashAlgorithm;
            RequiredKeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            Category = encryptionType;
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
            switch (value)
            {
                case "A128CBC-HS256":
                    return Aes128CbcHmacSha256;
                case "A192CBC-HS384":
                    return Aes192CbcHmacSha384;
                case "A256CBC-HS512":
                    return Aes256CbcHmacSha512;

                case "A128GCM":
                    return Aes128Gcm;
                case "A192GCM":
                    return Aes192Gcm;
                case "A256GCM":
                    return Aes256Gcm;

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
