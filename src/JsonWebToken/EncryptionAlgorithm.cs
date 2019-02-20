// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines encryption algorithm.
    /// </summary>
    public sealed class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>
    {
        /// <summary>
        /// 'A128CBC-HS256'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256 = new EncryptionAlgorithm(id: 11, "A128CBC-HS256", requiredKeySizeInBytes: 32, SignatureAlgorithm.HmacSha256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

        /// <summary>
        /// 'A192CBC-HS384'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384 = new EncryptionAlgorithm(id: 12, "A192CBC-HS384", requiredKeySizeInBytes: 48, SignatureAlgorithm.HmacSha384, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesHmac);

        /// <summary>
        /// 'A256CBC-HS512'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512 = new EncryptionAlgorithm(id: 13, "A256CBC-HS512", requiredKeySizeInBytes: 64, SignatureAlgorithm.HmacSha512, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesHmac);

#if NETCOREAPP3_0
        /// <summary>
        /// 'A128GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes128Gcm = new EncryptionAlgorithm(id: 21, "A128GCM", requiredKeySizeInBytes: 16, null, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesGcm);

        /// <summary>
        /// 'A192GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes192Gcm = new EncryptionAlgorithm(id: 22, "A192GCM", requiredKeySizeInBytes: 24, null, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesGcm);

        /// <summary>
        /// 'A256GCM'
        /// </summary>
        public static readonly EncryptionAlgorithm Aes256Gcm = new EncryptionAlgorithm(id: 23, "A256GCM", requiredKeySizeInBytes: 32, null, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesGcm);
#endif  

        // TODO : Verify the pertinence
        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id { get; }

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public EncryptionType Category { get; }

        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public ushort RequiredKeySizeInBytes { get; }

        /// <summary>
        /// Gets the wrapped key size, in bits.
        /// </summary>
        public ushort KeyWrappedSizeInBytes { get; }

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/>.
        /// </summary>
        public SignatureAlgorithm SignatureAlgorithm { get; }

        /// <summary>
        /// Gets the name of the encryption algorithm.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => Encoding.UTF8.GetBytes(Name);

        /// <summary>
        /// Gets the <see cref="EncryptionAlgorithm"/> list; 
        /// </summary>
        public static Dictionary<string, EncryptionAlgorithm> Algorithms { get; } = new Dictionary<string, EncryptionAlgorithm>
        {
            { Aes128CbcHmacSha256.Name, Aes128CbcHmacSha256 },
            { Aes192CbcHmacSha384.Name, Aes192CbcHmacSha384 },
            { Aes256CbcHmacSha512.Name, Aes256CbcHmacSha512 },
#if NETCOREAPP3_0
            { Aes128Gcm.Name, Aes128Gcm },
            { Aes192Gcm.Name, Aes192Gcm },
            { Aes256Gcm.Name, Aes256Gcm },
#endif
        };

        /// <summary>
        /// Initializes a new instance of <see cref="EncryptionAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="requiredKeySizeInBytes"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="requiredKeyWrappedSizeInBytes"></param>
        /// <param name="category"></param>
        public EncryptionAlgorithm(sbyte id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm hashAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionType category)
        {
            Id = id;
            Name = name;
            RequiredKeySizeInBytes = requiredKeySizeInBytes;
            SignatureAlgorithm = hashAlgorithm;
            KeyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            Category = category;
        }
        
        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="EncryptionAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is EncryptionAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> objects have the same value.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(EncryptionAlgorithm other)
        {
            if (other is null)
            {
                return false;
            }

            return Id == other.Id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="EncryptionAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Determines whether two specified <see cref="EncryptionAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator string(EncryptionAlgorithm value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator byte[] (EncryptionAlgorithm value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
            }

            return value.Utf8Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator EncryptionAlgorithm(byte[] value)
        {
            return Encoding.UTF8.GetString(value);
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator EncryptionAlgorithm(string value)
        {
            if (value == null)
            {
                return null;
            }

            if (!Algorithms.TryGetValue(value, out var algorithm))
            {
                Errors.ThrowNotSupportedAlgorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// 
        public unsafe static implicit operator EncryptionAlgorithm(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty)
            {
                return null;
            }

            fixed (byte* pValue = value)
            {
                if (value.Length == 13 && *pValue == (byte)'A')
                {
                    switch (*(long*)(pValue + 1))
                    {
                        case 5200887096557449777 when *(int*)(pValue + 9) == 909455955 /* A128CBC-HS256 */:
                            return Aes128CbcHmacSha256;
                        case 5200887096557058353 when *(int*)(pValue + 9) == 876098387 /* A128CBC-HS256 */:
                            return Aes192CbcHmacSha384;
                        case 5200887096557319474 when *(int*)(pValue + 9) == 842085715 /* A128CBC-HS256 */:
                            return Aes256CbcHmacSha512;
                    }
                }
#if NETCOREAPP3_0
                else if (value.Length == 7 && *pValue == (byte)'A' && *(short*)(pValue + 5) == 19779)
                {
                    switch (*(int*)(pValue + 1))
                    {
                        case 1194865201 /* A128GCM */:
                            return Aes128Gcm;
                        case 1194473777 /* A192GCM */:
                            return Aes192Gcm;
                        case 1194734898 /* A256GCM */:
                            return Aes256Gcm;
                    }
                }
#endif

                return (EncryptionAlgorithm)Encoding.UTF8.GetString(value.ToArray());
            }
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }
    }
}
