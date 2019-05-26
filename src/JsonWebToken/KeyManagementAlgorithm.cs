// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines key management algorithm.
    /// </summary>
    public sealed class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>
    {
        private static ReadOnlySpan<byte> Dir => new[] { (byte)'d', (byte)'i', (byte)'r' };

        /// <summary>
        /// 'dir'
        /// </summary>
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: 1, "dir", AlgorithmCategory.Aes, produceEncryptedKey: false);

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
        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: 21, "A128GCMKW", AlgorithmCategory.Aes, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: 22, "A192GCMKW", AlgorithmCategory.Aes, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: 23, "A256GCMKW", AlgorithmCategory.Aes, requiredKeySizeInBits: 256);

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
        /// Gets the wrapped algorithm.
        /// </summary>
        public KeyManagementAlgorithm WrappedAlgorithm { get; }

        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public byte[] Utf8Name => Encoding.UTF8.GetBytes(Name);

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
            { RsaPkcs1.Name, RsaPkcs1 }
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
                goto NotEqual;
            }

            if (y is null)
            {
                goto NotEqual;
            }

            return x.Id == y.Id;
        NotEqual:
            return false;
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
                goto Equal;
            }

            if (y is null)
            {
                goto Equal;
            }

            return x.Id != y.Id;
        Equal:
            return true;
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
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator KeyManagementAlgorithm(byte[] value)
        {
            if (value == null)
            {
                return null;
            }

            return (KeyManagementAlgorithm)new ReadOnlySpan<byte>(value);
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator KeyManagementAlgorithm(string value)
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
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public unsafe static explicit operator KeyManagementAlgorithm(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty)
            {
                return null;
            }

            fixed (byte* pValue = value)
            {
                switch (value.Length)
                {
                    case 3 when *(ushort*)pValue == 26980u && *(pValue + 2) == (byte)'r' /* dir */:
                        return Direct;
                    case 6 when *(ushort*)(pValue + 4) == 22347u:
                        switch (*(uint*)pValue)
                        {
                            case 942813505u:
                                return Aes128KW;
                            case 842608961u:
                                return Aes192KW;
                            case 909455937u:
                                return Aes256KW;
                        }
                        break;
                    case 6 when *(uint*)pValue == 826364754u && *(ushort*)(pValue + 4) == 13663u  /* RSA1_5 */:
                        return RsaPkcs1;
                    case 7 when *(uint*)pValue == 1212433221u && *(uint*)(pValue + 3) == 1397042504u /* ECDH-ES */ :
                        return EcdhEs;
                    case 8 when *(ulong*)pValue == 5784101104744747858u:
                        return RsaOaep;
                    case 9 when *(pValue + 4) == (byte)'G' && *(uint*)(pValue + 5) == 1464552771u /* CMKW */ :
                        switch (*(uint*)pValue)
                        {
                            case 942813505u:
                                return Aes128GcmKW;
                            case 842608961u:
                                return Aes192GcmKW;
                            case 909455937u:
                                return Aes256GcmKW;
                        }
                        break;
                    case 12 when *(ulong*)pValue == 5784101104744747858u: /* RSA-OAEP */
                        switch (*(uint*)(pValue + 8))
                        {
                            case 909455917u:
                                return RsaOaep256;
                            case 876098349u:
                                return RsaOaep384;
                            case 842085677u:
                                return RsaOaep512;
                        }
                        break;
                    case 14 when *(ulong*)pValue == 3121915027486163781u /* ECDH-ES+ */ :
                        switch (*(ulong*)(pValue + 6))
                        {
                            case 6290183092778904403u:
                                return EcdhEsAes128KW;
                            case 6290176525773908819u:
                                return EcdhEsAes192KW;
                            case 6290180906657327955u:
                                return EcdhEsAes256KW;
                        }
                        break;

                    default:
                        break;
                }
            }

            return null;
        }

        /// <summary>
        /// Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator byte[] (KeyManagementAlgorithm value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
            }

            return value.Utf8Name;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public unsafe static bool TryParse(ReadOnlySpan<byte> value, out KeyManagementAlgorithm algorithm)
        {
            if (value.IsEmpty)
            {
                algorithm = null;
                return true;
            }

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
                    case 9 when *(pValue + 4) == (byte)'G' && *(uint*)(pValue + 5) == 1464552771u /* CMKW */ :
                        switch (*(uint*)pValue)
                        {
                            case 942813505u /* A128 */ :
                                algorithm = Aes128GcmKW;
                                return true;
                            case 842608961u /* A192 */ :
                                algorithm = Aes192GcmKW;
                                return true;
                            case 909455937u /* A256 */ :
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
                    case 14 when *(ulong*)pValue == 5784101104744747858u /* ECDH-ES+ */ :
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

                    // Special case for ECDH-ES\u002bAxxxKW 
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

                    default:
                        break;
                }

                algorithm = null;
                return false;
            }
        }
    }
}
