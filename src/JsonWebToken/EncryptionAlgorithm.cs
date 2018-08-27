using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public readonly struct EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>
    {
        public static readonly EncryptionAlgorithm Empty = default;

        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(1, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, 32, SignatureAlgorithm.HmacSha256, 40, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(2, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, 48, SignatureAlgorithm.HmacSha384, 56, EncryptionTypes.AesHmac);
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(3, ContentEncryptionAlgorithms.Aes256CbcHmacSha512, 64, SignatureAlgorithm.HmacSha512, 72, EncryptionTypes.AesHmac);

        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(4, ContentEncryptionAlgorithms.Aes128Gcm, 16, default, 40, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(5, ContentEncryptionAlgorithms.Aes192Gcm, 24, default, 56, EncryptionTypes.AesGcm);
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(6, ContentEncryptionAlgorithms.Aes256Gcm, 32, default, 72, EncryptionTypes.AesGcm);

        public static readonly IDictionary<string, EncryptionAlgorithm> AdditionalAlgorithms = new Dictionary<string, EncryptionAlgorithm>();

        private readonly long _id;

        public readonly int RequiredKeySizeInBytes;
        public readonly int RequiredKeyWrappedSizeInBytes;
        public readonly SignatureAlgorithm SignatureAlgorithm;
        public readonly EncryptionTypes Category;
        public readonly string Name;

        private EncryptionAlgorithm(long id, string name, int requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, int requiredKeyWrappedSizeInBytes, EncryptionTypes encryptionType)
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
            return _id == other._id;
        }

        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        public static bool operator ==(in EncryptionAlgorithm x, in EncryptionAlgorithm y)
        {
            return x._id == y._id;
        }

        public static bool operator !=(in EncryptionAlgorithm x, in EncryptionAlgorithm y)
        {
            return x._id != y._id;
        }

        public static explicit operator string(in EncryptionAlgorithm value)
        {
            return value.Name;
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
