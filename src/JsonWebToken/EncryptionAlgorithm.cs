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
        private readonly sbyte _id;
        private readonly EncryptionType _category;
        private readonly ushort _requiredKeySizeInBytes;
        private readonly ushort _keyWrappedSizeInBytes;
        private readonly SignatureAlgorithm _signatureAlgorithm;
        private readonly byte[] _utf8Name;

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

        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id => _id;

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public EncryptionType Category => _category;
        
        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public ushort RequiredKeySizeInBytes => _requiredKeySizeInBytes;
        
        /// <summary>
        /// Gets the wrapped key size, in bits.
        /// </summary>
        public ushort KeyWrappedSizeInBytes => _keyWrappedSizeInBytes;
        
        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/>.
        /// </summary>
        public SignatureAlgorithm SignatureAlgorithm => _signatureAlgorithm;

        /// <summary>
        /// Gets the name of the encryption algorithm.
        /// </summary>
        public string Name => Encoding.UTF8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => _utf8Name;

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
            _id = id;
            _utf8Name= Encoding.UTF8.GetBytes(name);
            _requiredKeySizeInBytes = requiredKeySizeInBytes;
            _signatureAlgorithm = hashAlgorithm;
            _keyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            _category = category;
        }


        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public unsafe static bool TryParse(ReadOnlySpan<byte> value, out EncryptionAlgorithm algorithm)
        {
            if (value.IsEmpty)
            {
                algorithm = null;
                return true;
            }

            fixed (byte* pValue = value)
            {
                if (value.Length == 13)
                {
                    switch (*(ulong*)pValue)
                    {
                        case 3261523411619426625u when *(ulong*)(pValue + 5) == 3906083585088373570u:
                            algorithm = Aes128CbcHmacSha256;
                            return true;
                        case 3261523411519222081u when *(ulong*)(pValue + 5) == 3762813921454277442u:
                            algorithm = Aes192CbcHmacSha384;
                            return true;
                        case 3261523411586069057u when *(ulong*)(pValue + 5) == 3616730607564702530u:
                            algorithm = Aes256CbcHmacSha512;
                            return true;
                    }
                }
#if NETCOREAPP3_0
                else if (value.Length == 7)
                {
                    switch (*(uint*)pValue)
                    {
                        case 942813505u when *(uint*)(pValue + 3) == 1296254776u:
                            algorithm = Aes128Gcm;
                            return true;
                        case 842608961u when *(uint*)(pValue + 3) == 1296254770u:
                            algorithm = Aes192Gcm;
                            return true;
                        case 909455937u when *(uint*)(pValue + 3) == 1296254774u:
                            algorithm = Aes256Gcm;
                            return true;
                    }
                }
#endif

                algorithm = null;
                return false;
            }
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

            return _id == other._id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="EncryptionAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _id.GetHashCode();
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

            return x._id == y._id;
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

            return x._id != y._id;
        }

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator string(EncryptionAlgorithm value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[](EncryptionAlgorithm value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
            }

            return value._utf8Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm(byte[] value)
        {
            if (value == null)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                Errors.ThrowNotSupportedAlgorithm(Encoding.UTF8.GetString(value));
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm(string value)
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

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Computes a unique key for the combinaison of the <see cref="EncryptionAlgorithm"/> and the <see cref="KeyManagementAlgorithm"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public int ComputeKey(KeyManagementAlgorithm algorithm)
        {
            return (_id << 8) | (byte)algorithm.Id;
        }
    }
}
