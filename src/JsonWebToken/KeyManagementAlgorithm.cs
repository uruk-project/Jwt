// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Defines key management algorithm.
    /// </summary>
    public sealed class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>, IAlgorithm
    {
        private const uint dir = 7498084u;
        private const uint KW = 22347u;
        private const uint A128 = 942813505u;
        private const uint A192 = 842608961u;
        private const uint A256 = 909455937u;
        private const ulong ECDH_ES = 23438483855262533u;
        private const ulong RSA_OAEP = 5784101104744747858u;
        private const uint RSA1 = 826364754u;
        private const uint _5 = 13663u;
        private const ulong _128GCMKW = 6290206255906042417u;
        private const ulong _192GCMKW = 6290206255905650993u;
        private const ulong _256GCMKW = 6290206255905912114u;
        private const uint _256 = 909455917u;
        private const uint _384 = 876098349u;
        private const uint _512 = 842085677u;
        private const ulong ECDH_ES_ = 3121915027486163781u;
        private const ulong S_A128KW = 6290183092778904403u;
        private const ulong S_A192KW = 6290176525773908819u;
        private const ulong S_A256KW = 6290180906657327955u;
        private const ulong ECDH_ES_UTF8 = 6652737135344632645u;
        private const ulong u002bA12 = 3616743865759838325u;
        private const uint _28KW = 1464547378u;
        private const ulong u002bA19 = 4121147024025333877u;
        private const uint _92KW = 1464545849u;
        private const ulong u002bA25 = 3833198122850332789u;
        private const uint _56KW = 1464546869u;

        /// <summary>
        /// Empty
        /// </summary>
        internal static readonly KeyManagementAlgorithm Empty = new KeyManagementAlgorithm(id: 0, "Empty", AlgorithmCategory.None, produceEncryptedKey: false);

        /// <summary>
        /// 'dir'
        /// </summary>
        public static readonly KeyManagementAlgorithm Direct = new KeyManagementAlgorithm(id: Algorithms.Direct, "dir", AlgorithmCategory.Direct, produceEncryptedKey: false);

        /// <summary>
        /// 'A128KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128KW = new KeyManagementAlgorithm(id: Algorithms.Aes128KW, "A128KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192KW = new KeyManagementAlgorithm(id: Algorithms.Aes192KW, "A192KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256KW = new KeyManagementAlgorithm(id: Algorithms.Aes256KW, "A256KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes128GcmKW = new KeyManagementAlgorithm(id: Algorithms.Aes128GcmKW, "A128GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 128);

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes192GcmKW = new KeyManagementAlgorithm(id: Algorithms.Aes192GcmKW, "A192GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 192);

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        public static readonly KeyManagementAlgorithm Aes256GcmKW = new KeyManagementAlgorithm(id: Algorithms.Aes256GcmKW, "A256GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 256);

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaPkcs1 = new KeyManagementAlgorithm(id: Algorithms.RsaPkcs1, "RSA1_5", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: Algorithms.RsaOaep, "RSA-OAEP", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-128'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: Algorithms.RsaOaep256, "RSA-OAEP-256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-192'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep384 = new KeyManagementAlgorithm(id: Algorithms.RsaOaep384, "RSA-OAEP-384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'RSA-OAEP-256'
        /// </summary>
        public static readonly KeyManagementAlgorithm RsaOaep512 = new KeyManagementAlgorithm(id: Algorithms.RsaOaep512, "RSA-OAEP-512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>
        /// 'ECDH-ES'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: Algorithms.EcdhEs, "ECDH-ES", AlgorithmCategory.EllipticCurve | AlgorithmCategory.Direct, produceEncryptedKey: false);

        /// <summary>
        /// 'ECDH-ES+A128KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes128KW = new KeyManagementAlgorithm(id: Algorithms.EcdhEsAes128KW, "ECDH-ES+A128KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes128KW);

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW = new KeyManagementAlgorithm(id: Algorithms.EcdhEsAes192KW, "ECDH-ES+A192KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes192KW);

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// </summary>
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW = new KeyManagementAlgorithm(id: Algorithms.EcdhEsAes256KW, "ECDH-ES+A256KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: Aes256KW);

        private readonly int _id;
        private readonly ushort _requiredKeySizeInBits;
        private readonly AlgorithmCategory _category;
        private readonly KeyManagementAlgorithm? _wrappedAlgorithm;
        private readonly byte[] _utf8Name;
        private readonly bool _produceEncryptionKey;

        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public int Id => _id;

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
        public string Name => Utf8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the key management algorithm.
        /// </summary>
        public ReadOnlySpan<byte> Utf8Name => _utf8Name;

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
            RsaPkcs1,
            RsaOaep256,
            RsaOaep384,
            RsaOaep512
        };

        /// <summary>
        /// Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. 
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="keyType"></param>
        public KeyManagementAlgorithm(int id, string name, AlgorithmCategory keyType)
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
        public KeyManagementAlgorithm(int id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm? wrappedAlgorithm)
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
        public KeyManagementAlgorithm(int id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
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
        public KeyManagementAlgorithm(int id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
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
        public KeyManagementAlgorithm(int id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, KeyManagementAlgorithm? wrappedAlgorithm, bool produceEncryptedKey)
        {
            _id = id;
            _utf8Name = Utf8.GetBytes(name);
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
            return Equals(obj as KeyManagementAlgorithm);
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
            => _id.GetHashCode();

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator ==(KeyManagementAlgorithm? x, KeyManagementAlgorithm? y)
        {
            // Fast path: should be singletons
            if (ReferenceEquals(x, y))
            {
                return true;
            }

            if (x is null)
            {
                return false;
            }

            return x.Equals(y);
        }

        /// <summary>
        /// Determines whether two specified <see cref="KeyManagementAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(KeyManagementAlgorithm? x, KeyManagementAlgorithm? y)
        {
            // Fast path: should be singletons
            if (ReferenceEquals(x, y))
            {
                return false;
            }

            if (x is null)
            {
                return true;
            }

            return !x.Equals(y);
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
                ThrowHelper.ThrowNotSupportedException_Algorithm(Utf8.GetString(value));
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

            if (!TryParse(Utf8.GetBytes(value), out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[]?(KeyManagementAlgorithm? value)
        {
            if (value is null)
            {
                return null;
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
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            switch (value.Length)
            {
                case 3 when IntegerMarshal.ReadUInt24(value) == dir:
                    algorithm = Direct;
                    goto Found;
                case 6 when IntegerMarshal.ReadUInt16(value, 4) == KW:
                    switch (IntegerMarshal.ReadUInt32(value))
                    {
                        case A128:
                            algorithm = Aes128KW;
                            goto Found;
                        case A192:
                            algorithm = Aes192KW;
                            goto Found;
                        case A256:
                            algorithm = Aes256KW;
                            goto Found;
                    }
                    break;
                case 6 when IntegerMarshal.ReadUInt32(value) == RSA1 && IntegerMarshal.ReadUInt16(value, 4) == _5:
                    algorithm = RsaPkcs1;
                    goto Found;
                case 7 when IntegerMarshal.ReadUInt56(value) == ECDH_ES:
                    algorithm = EcdhEs;
                    goto Found;
                case 8 when IntegerMarshal.ReadUInt64(value) == RSA_OAEP:
                    algorithm = RsaOaep;
                    goto Found;
                case 9 when IntegerMarshal.ReadUInt8(value) == (byte)'A':
                    switch (IntegerMarshal.ReadUInt64(value, 1))
                    {
                        case _128GCMKW:
                            algorithm = Aes128GcmKW;
                            goto Found;
                        case _192GCMKW:
                            algorithm = Aes192GcmKW;
                            goto Found;
                        case _256GCMKW:
                            algorithm = Aes256GcmKW;
                            goto Found;
                    }
                    break;
                case 12 when IntegerMarshal.ReadUInt64(value) == RSA_OAEP:
                    switch (IntegerMarshal.ReadUInt32(value, 8))
                    {
                        case _256:
                            algorithm = RsaOaep256;
                            goto Found;
                        case _384:
                            algorithm = RsaOaep384;
                            goto Found;
                        case _512:
                            algorithm = RsaOaep512;
                            goto Found;
                    }
                    break;
                case 14 when IntegerMarshal.ReadUInt64(value) == ECDH_ES_:
                    switch (IntegerMarshal.ReadUInt64(value, 6))
                    {
                        case S_A128KW:
                            algorithm = EcdhEsAes128KW;
                            goto Found;
                        case S_A192KW:
                            algorithm = EcdhEsAes192KW;
                            goto Found;
                        case S_A256KW:
                            algorithm = EcdhEsAes256KW;
                            goto Found;
                    }
                    break;

                // Special case for escaped 'ECDH-ES\u002bAxxxKW' 
                case 19 when IntegerMarshal.ReadUInt64(value) == ECDH_ES_UTF8 /* ECDH-ES\ */ :
                    switch (IntegerMarshal.ReadUInt64(value, 8))
                    {
                        case u002bA12 when IntegerMarshal.ReadUInt32(value, 15) == _28KW:
                            algorithm = EcdhEsAes128KW;
                            goto Found;
                        case u002bA19 when IntegerMarshal.ReadUInt32(value, 15) == _92KW:
                            algorithm = EcdhEsAes192KW;
                            goto Found;
                        case u002bA25 when IntegerMarshal.ReadUInt32(value, 15) == _56KW:
                            algorithm = EcdhEsAes256KW;
                            goto Found;
                    }
                    break;
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>
        /// Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="KeyManagementAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ref Utf8JsonReader reader, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            var value = reader.ValueSpan;
            if (TryParse(value, out algorithm))
            {
                return true;
            }

            return TryParseSlow(ref reader, out algorithm);
        }
    }
}
