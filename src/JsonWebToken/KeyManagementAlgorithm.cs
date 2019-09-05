// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Defines key management algorithm.
    /// </summary>
    public sealed class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>
    {
        /// <summary>
        /// 'dir'
        /// </summary>
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, "dir", AlgorithmCategory.None, produceEncryptedKey: false);

        /// <summary>
        /// 'A128KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: 11, "A128KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: 12, "A192KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: 13, "A256KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, "A128GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, "A192GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, "A256GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: 31, "RSA1_5", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: 32, "RSA-OAEP", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-128'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: 33, "RSA-OAEP-256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-192'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep384 = new KeyManagementAlgorithm(id: 34, "RSA-OAEP-384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-256'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep512 = new KeyManagementAlgorithm(id: 35, "RSA-OAEP-512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

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

        private readonly byte _id;
        private readonly ushort _requiredKeySizeInBits;
        private readonly AlgorithmCategory _category;
        private readonly KeyManagementAlgorithm? _wrappedAlgorithm;
        private readonly byte[] _utf8Name;
        private readonly bool _produceEncryptionKey;

        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public byte Id => _id;

        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public ushort RequiredKeySizeInBits => _requiredKeySizeInBits;

        /// <summary>
        /// Gets the algorithm category.
        /// </summary>
        public AlgorithmCategory Category => _category;

        /// <summary>
        /// Gets the wrapped algorithm.
        /// </summary>
        public KeyManagementAlgorithm? WrappedAlgorithm => _wrappedAlgorithm;

        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public string Name => Encoding.UTF8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public byte[] Utf8Name => _utf8Name;

        /// <summary>
        /// Gets whether the algorithm produce an encryption key.
        /// </summary>
        public bool ProduceEncryptionKey => _produceEncryptionKey;

        private static readonly KeyManagementAlgorithm[] _algorithms = new[]
        {
            EcdhEsAes128KW,
            EcdhEsAes192KW,
            EcdhEsAes256KW,
            EcdhEs,
            Aes128KW,
            Aes192KW,
            Aes256KW,
            Aes128GcmKW,
            Aes192GcmKW,
            Aes256GcmKW,
            Direct,
            RsaOaep,
            RsaOaep256,
            RsaOaep384,
            RsaOaep512,
            RsaPkcs1
        };

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        public KeyManagementAlgorithm(byte id, string name, AlgorithmCategory keyType)
            : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm: null, produceEncryptedKey: true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="wrappedAlgorithm"></param>
        public KeyManagementAlgorithm(byte id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm? wrappedAlgorithm)
                : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm, produceEncryptedKey: true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="requiredKeySizeInBits"></param>
        public KeyManagementAlgorithm(byte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
            : this(id, name, keyType, requiredKeySizeInBits, wrappedAlgorithm: null, produceEncryptedKey: true)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        /// <param name="produceEncryptedKey"></param>
        public KeyManagementAlgorithm(byte id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
            : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm: null, produceEncryptedKey)
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
        public KeyManagementAlgorithm(byte id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, KeyManagementAlgorithm? wrappedAlgorithm, bool produceEncryptedKey)
        {
            _id = id;
            _utf8Name = Encoding.UTF8.GetBytes(name);
            _category = keyType;
            _requiredKeySizeInBits = requiredKeySizeInBits;
            _wrappedAlgorithm = wrappedAlgorithm;
            _produceEncryptionKey = produceEncryptedKey;
        }

        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="KeyManagementAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
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
        public bool Equals(KeyManagementAlgorithm? other)
        {
            if (other is null)
            {
                return false;
            }

            return _id == other._id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="KeyManagementAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator ==(KeyManagementAlgorithm? x, KeyManagementAlgorithm? y)
        {
            if (x is null && y is null)
            {
                return true;
            }

            if (x is null)
            {
                goto NotEqual;
            }

            if (y is null)
            {
                goto NotEqual;
            }

            return x._id == y._id;
        NotEqual:
            return false;
        }

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(KeyManagementAlgorithm? x, KeyManagementAlgorithm? y)
        {
            if (x is null && y is null)
            {
                return false;
            }

            if (x is null)
            {
                goto Equal;
            }

            if (y is null)
            {
                goto Equal;
            }

            return x._id != y._id;
        Equal:
            return true;
        }

        /// <summary>
        /// Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator string?(KeyManagementAlgorithm? value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator KeyManagementAlgorithm?(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(Encoding.UTF8.GetString(value));
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator KeyManagementAlgorithm?(string? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(Encoding.UTF8.GetBytes(value), out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[](KeyManagementAlgorithm? value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
            }

            return value._utf8Name;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            var algorithms = _algorithms;
            for (int i = 0; i < algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(algorithms[i]._utf8Name))
                {
                    algorithm = algorithms[i];
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public unsafe static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            fixed (byte* pValue = value)
            {
                switch (value.Length)
                {
                    case 3 when *(ushort*)pValue == 26980u && *(pValue + 2) == (byte)'r' /* dir */:
                        algorithm = Direct;
                        return true;
                    case 6 when *(ushort*)(pValue + 4) == 22347u:
                        switch (*(uint*)pValue)
                        {
                            case 942813505u:
                                algorithm = Aes128KW;
                                return true;
                            case 842608961u:
                                algorithm = Aes192KW;
                                return true;
                            case 909455937u:
                                algorithm = Aes256KW;
                                return true;
                        }
                        break;
                    case 6 when *(uint*)pValue == 826364754u && *(ushort*)(pValue + 4) == 13663u  /* RSA1_5 */:
                        algorithm = RsaPkcs1;
                        return true;
                    case 7 when *(uint*)pValue == 1212433221u && *(uint*)(pValue + 3) == 1397042504u /* ECDH-ES */ :
                        algorithm = EcdhEs;
                        return true;
                    case 8 when *(ulong*)pValue == 5784101104744747858u  /* RSA-OAEP */ :
                        algorithm = RsaOaep;
                        return true;
                    case 9 when *pValue == (byte)'A':
                        switch (*(ulong*)(pValue + 1))
                        {
                            /* A128GCMKW */
                            case 6290206255906042417u:
                                algorithm = Aes128GcmKW;
                                return true;
                            /* A192GCMKW */
                            case 6290206255905650993u:
                                algorithm = Aes192GcmKW;
                                return true;
                            /* A256GCMKW */
                            case 6290206255905912114u:
                                algorithm = Aes256GcmKW;
                                return true;
                        }
                        break;
                    case 12 when *(ulong*)pValue == 5784101104744747858u:
                        switch (*(uint*)(pValue + 8))
                        {
                            case 909455917u:
                                algorithm = RsaOaep256;
                                return true;
                            case 876098349u:
                                algorithm = RsaOaep384;
                                return true;
                            case 842085677u:
                                algorithm = RsaOaep512;
                                return true;
                        }
                        break;
                    case 14 when *(ulong*)pValue == 3121915027486163781u /* ECDH-ES+ */ :
                        switch (*(ulong*)(pValue + 6))
                        {
                            case 6290183092778904403u:
                                algorithm = EcdhEsAes128KW;
                                return true;
                            case 6290176525773908819u:
                                algorithm = EcdhEsAes192KW;
                                return true;
                            case 6290180906657327955u:
                                algorithm = EcdhEsAes256KW;
                                return true;
                        }
                        break;

                    // Special case for escaped 'ECDH-ES\u002bAxxxKW' 
                    case 19 when *(ulong*)pValue == 6652737135344632645u /* ECDH-ES\ */ :
                        switch (*(ulong*)(pValue + 8))
                        {
                            case 3616743865759838325u when (*(uint*)(pValue + 15)) == 1464547378u:
                                algorithm = EcdhEsAes128KW;
                                return true;
                            case 4121147024025333877u when (*(uint*)(pValue + 15)) == 1464545849u:
                                algorithm = EcdhEsAes192KW;
                                return true;
                            case 3833198122850332789u when (*(uint*)(pValue + 15)) == 1464546869u:
                                algorithm = EcdhEsAes256KW;
                                return true;
                        }
                        break;

                }

                algorithm = null;
                return false;
            }
        }
    }
}
