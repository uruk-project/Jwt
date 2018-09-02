using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>
    {
        public static readonly EncryptionAlgorithm Empty = new EncryptionAlgorithm(0, string.Empty, 0, SignatureAlgorithm.Empty, 0, EncryptionTypes.None);

        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(id: 11, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, requiredKeySizeInBytes: 32, SignatureAlgorithm.HmacSha256, requiredKeyWrappedSizeInBytes: 40, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(id: 12, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, requiredKeySizeInBytes: 48, SignatureAlgorithm.HmacSha384, requiredKeyWrappedSizeInBytes: 56, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(id: 13, ContentEncryptionAlgorithms.Aes256CbcHmacSha512, requiredKeySizeInBytes: 64, SignatureAlgorithm.HmacSha512, requiredKeyWrappedSizeInBytes: 72, EncryptionTypes.AesHmac);

        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(id: 21, ContentEncryptionAlgorithms.Aes128Gcm, requiredKeySizeInBytes: 16, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 40, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(id: 22, ContentEncryptionAlgorithms.Aes192Gcm, requiredKeySizeInBytes: 24, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 56, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(id: 23, ContentEncryptionAlgorithms.Aes256Gcm, requiredKeySizeInBytes: 32, SignatureAlgorithm.Empty, requiredKeyWrappedSizeInBytes: 72, EncryptionTypes.AesGcm);

        public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

        private readonly sbyte _id;
        public readonly EncryptionTypes Category;

        public readonly ushort RequiredKeySizeInBytes;
        public readonly ushort RequiredKeyWrappedSizeInBytes;
        public readonly SignatureAlgorithm SignatureAlgorithm;
        public readonly string Name;

        private EncryptionAlgorithm(sbyte id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionTypes encryptionType)
        {
            _id = id;
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

            return _id == other._id;
        }

        public override int GetHashCode()
        {
            return _id.GetHashCode();
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

            return x._id == y._id;
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

            return x._id != y._id;
        }

        public static explicit operator string(EncryptionAlgorithm value)
        {
            return value?.Name;
        }

        public static explicit operator EncryptionAlgorithm(string value)
        {
            switch (value)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return Aes128CbcHmacSha256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return Aes192CbcHmacSha384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return Aes256CbcHmacSha512;

                case ContentEncryptionAlgorithms.Aes128Gcm:
                    return Aes128Gcm;
                case ContentEncryptionAlgorithms.Aes192Gcm:
                    return Aes192Gcm;
                case ContentEncryptionAlgorithms.Aes256Gcm:
                    return Aes256Gcm;

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
