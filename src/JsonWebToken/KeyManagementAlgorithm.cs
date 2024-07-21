// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines key management algorithm.</summary>
    public sealed partial class KeyManagementAlgorithm : IEquatable<KeyManagementAlgorithm>, IAlgorithm
    {
        [MagicNumber("dir")]
        private const uint _dir = 7498084U;

        [MagicNumber("KW")]
        private const ushort _KW = 22347;

        [MagicNumber("A128")]
        private const uint _A128 = 942813505u;

        [MagicNumber("A192")]
        private const uint _A192 = 842608961u;

        [MagicNumber("A256")]
        private const uint _A256 = 909455937u;

        [MagicNumber("ECDH-ES")]
        private const ulong _ECDH_ES = 23438483855262533u;

        [MagicNumber("RSA-OAEP")]
        private const ulong _RSA_OAEP = 5784101104744747858u;

        [MagicNumber("RSA1")]
        private const uint _RSA1 = 826364754u;

        [MagicNumber("_5")]
        private const ushort __5 = 13663;

        [MagicNumber("128GCMKW")]
        private const ulong __128GCMKW = 6290206255906042417u;

        [MagicNumber("192GCMKW")]
        private const ulong __192GCMKW = 6290206255905650993u;

        [MagicNumber("256GCMKW")]
        private const ulong __256GCMKW = 6290206255905912114u;

        [MagicNumber("-256")]
        private const uint __256 = 909455917u;

        [MagicNumber("-384")]
        private const uint __384 = 876098349u;

        [MagicNumber("-512")]
        private const uint __512 = 842085677u;

        [MagicNumber("ECDH-ES+")]
        private const ulong _ECDH_ES_ = 3121915027486163781u;

        [MagicNumber("S+A128KW")]
        private const ulong _S_A128KW = 6290183092778904403u;

        [MagicNumber("S+A192KW")]
        private const ulong _S_A192KW = 6290176525773908819u;

        [MagicNumber("S+A256KW")]
        private const ulong _S_A256KW = 6290180906657327955u;

        [MagicNumber("ECDH-ES\\\\")]
        private const ulong _ECDH_ES_UTF8 = 6652737135344632645u;

        [MagicNumber("u002bA12")]
        private const ulong _u002bA12 = 3616743865759838325u;

        [MagicNumber("28KW")]
        private const uint __28KW = 1464547378u;

        [MagicNumber("u002bA19")]
        private const ulong _u002bA19 = 4121147024025333877u;

        [MagicNumber("92KW")]
        private const uint __92KW = 1464545849u;

        [MagicNumber("u002bA25")]
        private const ulong _u002bA25 = 3833198122850332789u;

        [MagicNumber("56KW")]
        private const uint __56KW = 1464546869u;

        private const ulong u002bUpperMask = 137438953504u;

        /// <summary>Empty</summary>
        internal static readonly KeyManagementAlgorithm Empty = new KeyManagementAlgorithm(id: 0, "Empty", AlgorithmCategory.None, produceEncryptedKey: false);

        /// <summary>'dir'</summary>
        public static readonly KeyManagementAlgorithm Dir = new KeyManagementAlgorithm(id: AlgorithmId.Dir, "dir", AlgorithmCategory.Direct, produceEncryptedKey: false);

        /// <summary>'A128KW'</summary>
        public static readonly KeyManagementAlgorithm A128KW = new KeyManagementAlgorithm(id: AlgorithmId.A128KW, "A128KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 128);

        /// <summary>'A192KW'</summary>
        public static readonly KeyManagementAlgorithm A192KW = new KeyManagementAlgorithm(id: AlgorithmId.A192KW, "A192KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 192);

        /// <summary>'A256KW'</summary>
        public static readonly KeyManagementAlgorithm A256KW = new KeyManagementAlgorithm(id: AlgorithmId.A256KW, "A256KW", AlgorithmCategory.Aes, requiredKeySizeInBits: 256);

        /// <summary>'A128GCMKW'</summary>
        public static readonly KeyManagementAlgorithm A128GcmKW = new KeyManagementAlgorithm(id: AlgorithmId.A128GcmKW, "A128GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 128);

        /// <summary>'A192GCMKW'</summary>
        public static readonly KeyManagementAlgorithm A192GcmKW = new KeyManagementAlgorithm(id: AlgorithmId.A192GcmKW, "A192GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 192);

        /// <summary>'A256GCMKW'</summary>
        public static readonly KeyManagementAlgorithm A256GcmKW = new KeyManagementAlgorithm(id: AlgorithmId.A256GcmKW, "A256GCMKW", AlgorithmCategory.AesGcm, requiredKeySizeInBits: 256);

        /// <summary>'RSA1_5'. This algorithm is deprecated.</summary>
        public static readonly KeyManagementAlgorithm Rsa1_5 = new KeyManagementAlgorithm(id: AlgorithmId.Rsa1_5, "RSA1_5", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>'RSA-OAEP'</summary>
        public static readonly KeyManagementAlgorithm RsaOaep = new KeyManagementAlgorithm(id: AlgorithmId.RsaOaep, "RSA-OAEP", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>'RSA-OAEP-128'</summary>
        public static readonly KeyManagementAlgorithm RsaOaep256 = new KeyManagementAlgorithm(id: AlgorithmId.RsaOaep256, "RSA-OAEP-256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>'RSA-OAEP-192'</summary>
        public static readonly KeyManagementAlgorithm RsaOaep384 = new KeyManagementAlgorithm(id: AlgorithmId.RsaOaep384, "RSA-OAEP-384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>'RSA-OAEP-256'</summary>
        public static readonly KeyManagementAlgorithm RsaOaep512 = new KeyManagementAlgorithm(id: AlgorithmId.RsaOaep512, "RSA-OAEP-512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048);

        /// <summary>'ECDH-ES'</summary>
        public static readonly KeyManagementAlgorithm EcdhEs = new KeyManagementAlgorithm(id: AlgorithmId.EcdhEs, "ECDH-ES", AlgorithmCategory.EllipticCurve | AlgorithmCategory.EllipticCurve, produceEncryptedKey: false);

        /// <summary>'ECDH-ES+A128KW'</summary>
        public static readonly KeyManagementAlgorithm EcdhEsA128KW = new KeyManagementAlgorithm(id: AlgorithmId.EcdhEsA128KW, "ECDH-ES+A128KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: A128KW);

        /// <summary>'ECDH-ES+A192KW'</summary>
        public static readonly KeyManagementAlgorithm EcdhEsA192KW = new KeyManagementAlgorithm(id: AlgorithmId.EcdhEsA192KW, "ECDH-ES+A192KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: A192KW);

        /// <summary>'ECDH-ES+A256KW'</summary>
        public static readonly KeyManagementAlgorithm EcdhEsA256KW = new KeyManagementAlgorithm(id: AlgorithmId.EcdhEsA256KW, "ECDH-ES+A256KW", AlgorithmCategory.EllipticCurve, wrappedAlgorithm: A256KW);

        /// <summary>'PBES2-HS256+A128KW'</summary>
        public static readonly KeyManagementAlgorithm Pbes2HS256A128KW = new KeyManagementAlgorithm(id: AlgorithmId.Pbes2HS256A128KW, "PBES2-HS256+A128KW", AlgorithmCategory.Pbkdf2, wrappedAlgorithm: A128KW, sha2: Sha256.Shared);

        /// <summary>'PBES2-HS394+A192KW'</summary>
        public static readonly KeyManagementAlgorithm Pbes2HS384A192KW = new KeyManagementAlgorithm(id: AlgorithmId.Pbes2HS384A192KW, "PBES2-HS384+A192KW", AlgorithmCategory.Pbkdf2, wrappedAlgorithm: A192KW, sha2: Sha384.Shared);

        /// <summary>'PBES2-HS512+A256KW'</summary>
        public static readonly KeyManagementAlgorithm Pbes2HS512A256KW = new KeyManagementAlgorithm(id: AlgorithmId.Pbes2HS512A256KW, "PBES2-HS512+A256KW", AlgorithmCategory.Pbkdf2, wrappedAlgorithm: A256KW, sha2: Sha512.Shared);

        private readonly AlgorithmId _id;
        private readonly ushort _requiredKeySizeInBits;
        private readonly KeyManagementAlgorithm? _wrappedAlgorithm;
        private readonly JsonEncodedText _utf8Name;
        private readonly AlgorithmCategory _category;
        private readonly bool _produceEncryptionKey;
        private readonly Sha2? _sha2;

        /// <summary>Gets the algorithm identifier. </summary>
        public AlgorithmId Id => _id;

        /// <summary>Gets the required key size, in bits.</summary>
        public ushort RequiredKeySizeInBits => _requiredKeySizeInBits;

        /// <summary>Gets the algorithm category.</summary>
        public AlgorithmCategory Category => _category;

        /// <summary>Gets the wrapped algorithm.</summary>
        public KeyManagementAlgorithm? WrappedAlgorithm => _wrappedAlgorithm;

        /// <summary>Gets the hash algorithm.</summary>
        public Sha2? HashAlgorithm => _sha2;

        /// <summary>Gets the name of the key management algorithm.</summary>
        public JsonEncodedText Name => _utf8Name;

        /// <summary>Gets the name of the key management algorithm.</summary>
        public ReadOnlySpan<byte> Utf8Name => _utf8Name.EncodedUtf8Bytes;

        /// <summary>Gets whether the algorithm produce an encryption key.</summary>
        public bool ProduceEncryptionKey => _produceEncryptionKey;

        internal static readonly KeyManagementAlgorithm[] _algorithms = new[]
        {
            EcdhEsA128KW,
            EcdhEsA256KW,
            EcdhEsA192KW,
            EcdhEs,
            A128KW,
            A256KW,
            A192KW,
            A128GcmKW,
            A256GcmKW,
            A192GcmKW,
            Dir,
            RsaOaep,
            Rsa1_5,
            RsaOaep256,
            RsaOaep512,
            RsaOaep384,
            Pbes2HS256A128KW,
            Pbes2HS512A256KW,
            Pbes2HS384A192KW
        };

        /// <summary>The supported <see cref="KeyManagementAlgorithm"/>.</summary>
        public static ReadOnlyCollection<KeyManagementAlgorithm> SupportedAlgorithms => Array.AsReadOnly(_algorithms);

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType)
            : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm: null, sha2: null, produceEncryptedKey: true)
        {
        }

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm)
                : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm, sha2: null, produceEncryptedKey: true)
        {
        }

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm, Sha2 sha2)
                : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm, sha2: sha2, produceEncryptedKey: true)
        {
        }

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
            : this(id, name, keyType, requiredKeySizeInBits, wrappedAlgorithm: null, sha2: null, produceEncryptedKey: true)
        {
        }

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
            : this(id, name, keyType, requiredKeySizeInBits: 0, wrappedAlgorithm: null, sha2: null, produceEncryptedKey)
        {
        }

        /// <summary>Initializes a new instance of <see cref="KeyManagementAlgorithm"/>. </summary>
        public KeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits, KeyManagementAlgorithm? wrappedAlgorithm, Sha2? sha2, bool produceEncryptedKey)
        {
            _id = id;
            _utf8Name = JsonEncodedText.Encode(name, JsonSerializationBehavior.JsonEncoder);
            _category = keyType;
            _requiredKeySizeInBits = requiredKeySizeInBits;
            _wrappedAlgorithm = wrappedAlgorithm;
            _produceEncryptionKey = produceEncryptedKey;
            _sha2 = sha2;
        }

        /// <summary>Determines whether this instance and a specified object, which must also be a<see cref="KeyManagementAlgorithm"/> object, have the same value.</summary>
        public override bool Equals(object? obj)
            => Equals(obj as KeyManagementAlgorithm);

        /// <summary>Determines whether two specified <see cref="KeyManagementAlgorithm"/> objects have the same value.</summary>
        public bool Equals(KeyManagementAlgorithm? other)
            => other is not null && _id == other._id;

        /// <summary>Returns the hash code for this <see cref="KeyManagementAlgorithm"/>.</summary>
        public override int GetHashCode()
            => _id.GetHashCode();

        /// <summary>Determines whether two specified <see cref="KeyManagementAlgorithm"/> have the same value.</summary>
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

        /// <summary>Determines whether two specified <see cref="KeyManagementAlgorithm"/> have different values.</summary>
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

        /// <summary>Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="string"/> representation.</summary>
        public static explicit operator string?(KeyManagementAlgorithm? value)
            => value?.Name.ToString();

        /// <summary>Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
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

        /// <summary>Cast the <see cref="string"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
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

        /// <summary>Cast the <see cref="KeyManagementAlgorithm"/> into its <see cref="byte"/> array representation.</summary>
        public static explicit operator byte[]?(KeyManagementAlgorithm? value)
            => value?._utf8Name.EncodedUtf8Bytes.ToArray();

        /// <inheritsddoc />
        public override string ToString()
            => Name.ToString();

        /// <summary>Parses the current value of the <see cref="Utf8JsonReader"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            var algorithms = _algorithms;
            for (int i = 0; i < algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(algorithms[i]._utf8Name.EncodedUtf8Bytes))
                {
                    algorithm = algorithms[i];
                    return true;
                }
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        }

        /// <summary>Parses the <see cref="ReadOnlySpan{T}"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            switch (value.Length)
            {
                case 3 when IntegerMarshal.ReadUInt24(value) == _dir:
                    algorithm = Dir;
                    goto Found;
                case 6 when IntegerMarshal.ReadUInt16(value, 4) == _KW:
                    switch (IntegerMarshal.ReadUInt32(value))
                    {
                        case _A128:
                            algorithm = A128KW;
                            goto Found;
                        case _A192:
                            algorithm = A192KW;
                            goto Found;
                        case _A256:
                            algorithm = A256KW;
                            goto Found;
                    }
                    break;
                case 6 when IntegerMarshal.ReadUInt32(value) == _RSA1 && IntegerMarshal.ReadUInt16(value, 4) == __5:
                    algorithm = Rsa1_5;
                    goto Found;
                case 7 when IntegerMarshal.ReadUInt56(value) == _ECDH_ES:
                    algorithm = EcdhEs;
                    goto Found;
                case 8 when IntegerMarshal.ReadUInt64(value) == _RSA_OAEP:
                    algorithm = RsaOaep;
                    goto Found;
                case 9 when IntegerMarshal.ReadUInt8(value) == (byte)'A':
                    switch (IntegerMarshal.ReadUInt64(value, 1))
                    {
                        case __128GCMKW:
                            algorithm = A128GcmKW;
                            goto Found;
                        case __192GCMKW:
                            algorithm = A192GcmKW;
                            goto Found;
                        case __256GCMKW:
                            algorithm = A256GcmKW;
                            goto Found;
                    }
                    break;
                case 12 when IntegerMarshal.ReadUInt64(value) == _RSA_OAEP:
                    switch (IntegerMarshal.ReadUInt32(value, 8))
                    {
                        case __256:
                            algorithm = RsaOaep256;
                            goto Found;
                        case __384:
                            algorithm = RsaOaep384;
                            goto Found;
                        case __512:
                            algorithm = RsaOaep512;
                            goto Found;
                    }
                    break;
                case 14 when IntegerMarshal.ReadUInt64(value) == _ECDH_ES_:
                    switch (IntegerMarshal.ReadUInt64(value, 6))
                    {
                        case _S_A128KW:
                            algorithm = EcdhEsA128KW;
                            goto Found;
                        case _S_A192KW:
                            algorithm = EcdhEsA192KW;
                            goto Found;
                        case _S_A256KW:
                            algorithm = EcdhEsA256KW;
                            goto Found;
                    }
                    break;

                // 'PBES2-HS384+A192KW' 
                case 18 when IntegerMarshal.ReadUInt64(value) == 6001096197639848528uL /* PBES2-HS 384+A192KW*/
                        && IntegerMarshal.ReadUInt16(value, 16) == _KW:
                    switch (IntegerMarshal.ReadUInt64(value, 8))
                    {
                        case 4049353170927105330uL:
                            algorithm = Pbes2HS256A128KW;
                            goto Found;
                        case 3618977931536382003uL:
                            algorithm = Pbes2HS384A192KW;
                            goto Found;
                        case 3906083507292746037:
                            algorithm = Pbes2HS512A256KW;
                            goto Found;
                    }
                    break;

                // Special case for escaped 'ECDH-ES\u002bAxxxKW' 
                case 19 when IntegerMarshal.ReadUInt64(value) == _ECDH_ES_UTF8 /* ECDH-ES\ */ :
                    switch (IntegerMarshal.ReadUInt64(value, 8) | u002bUpperMask)
                    {
                        case _u002bA12 when IntegerMarshal.ReadUInt32(value, 15) == __28KW:
                            algorithm = EcdhEsA128KW;
                            goto Found;
                        case _u002bA19 when IntegerMarshal.ReadUInt32(value, 15) == __92KW:
                            algorithm = EcdhEsA192KW;
                            goto Found;
                        case _u002bA25 when IntegerMarshal.ReadUInt32(value, 15) == __56KW:
                            algorithm = EcdhEsA256KW;
                            goto Found;
                    }
                    break;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="string"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParse(string? value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            switch (value)
            {
                case "dir":
                    algorithm = Dir;
                    goto Found;
                case "A128KW":
                    algorithm = A128KW;
                    goto Found;
                case "A192KW":
                    algorithm = A192KW;
                    goto Found;
                case "A256KW":
                    algorithm = A256KW;
                    goto Found;
                case "RSA1_5":
                    algorithm = Rsa1_5;
                    goto Found;
                case "ECDH-ES":
                    algorithm = EcdhEs;
                    goto Found;
                case "RSA-OAEP":
                    algorithm = RsaOaep;
                    goto Found;
                case "A128GCMKW":
                    algorithm = A128GcmKW;
                    goto Found;
                case "A192GCMKW":
                    algorithm = A192GcmKW;
                    goto Found;
                case "A256GCMKW":
                    algorithm = A256GcmKW;
                    goto Found;
                case "RSA-OAEP-256":
                    algorithm = RsaOaep256;
                    goto Found;
                case "RSA-OAEP-384":
                    algorithm = RsaOaep384;
                    goto Found;
                case "RSA-OAEP-512":
                    algorithm = RsaOaep512;
                    goto Found;
                case "ECDH-ES+A128KW":
                    algorithm = EcdhEsA128KW;
                    goto Found;
                case "ECDH-ES+A192KW":
                    algorithm = EcdhEsA192KW;
                    goto Found;
                case "ECDH-ES+A256KW":
                    algorithm = EcdhEsA256KW;
                    goto Found;
                case "PBES2-HS256+A128KW":
                    algorithm = Pbes2HS256A128KW;
                    goto Found;
                case "PBES2-HS384+A192KW":
                    algorithm = Pbes2HS384A192KW;
                    goto Found;
                case "PBES2-HS512+A256KW":
                    algorithm = Pbes2HS512A256KW;
                    goto Found;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="JwtElement"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParse(JwtElement value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            if (value.ValueEquals(Dir._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Dir;
                goto Found;
            }
            else if (value.ValueEquals(A128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128KW;
                goto Found;
            }
            else if (value.ValueEquals(A192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192KW;
                goto Found;
            }
            else if (value.ValueEquals(A256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256KW;
                goto Found;
            }
            else if (value.ValueEquals(Rsa1_5._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Rsa1_5;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEs._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEs;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep;
                goto Found;
            }
            else if (value.ValueEquals(A128GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(A192GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(A256GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep256._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep256;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep384._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep384;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep512._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep512;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA128KW;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA192KW;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA256KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS256A128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS256A128KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS384A192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS384A192KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS512A256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS512A256KW;
                goto Found;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="JsonElement"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParse(JsonElement value, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            if (value.ValueEquals(Dir._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Dir;
                goto Found;
            }
            else if (value.ValueEquals(A128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128KW;
                goto Found;
            }
            else if (value.ValueEquals(A192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192KW;
                goto Found;
            }
            else if (value.ValueEquals(A256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256KW;
                goto Found;
            }
            else if (value.ValueEquals(Rsa1_5._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Rsa1_5;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEs._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEs;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep;
                goto Found;
            }
            else if (value.ValueEquals(A128GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(A192GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(A256GcmKW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256GcmKW;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep256._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep256;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep384._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep384;
                goto Found;
            }
            else if (value.ValueEquals(RsaOaep512._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = RsaOaep512;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA128KW;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA192KW;
                goto Found;
            }
            else if (value.ValueEquals(EcdhEsA256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = EcdhEsA256KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS256A128KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS256A128KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS384A192KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS384A192KW;
                goto Found;
            }
            else if (value.ValueEquals(Pbes2HS512A256KW._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Pbes2HS512A256KW;
                goto Found;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the current value of the <see cref="Utf8JsonReader"/> into its <see cref="KeyManagementAlgorithm"/> representation.</summary>
        public static bool TryParse(ref Utf8JsonReader reader, [NotNullWhen(true)] out KeyManagementAlgorithm? algorithm)
        {
            var value = reader.ValueSpan;
            if (TryParse(value, out algorithm))
            {
                return true;
            }

            return TryParseSlow(ref reader, out algorithm);
        }

        internal static KeyManagementAlgorithm Create(string name)
            => new KeyManagementAlgorithm(AlgorithmId.Undefined, name, AlgorithmCategory.None, 0, null, null, false);
    }
}
