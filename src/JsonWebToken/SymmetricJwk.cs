// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a symmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class SymmetricJwk : Jwk
    {
#if NETSTANDARD2_0 || NET461 || NETCOREAPP2_1
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif

        private readonly byte[] _k;

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(ReadOnlySpan<byte> k)
        {
            _k = k.ToArray();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(byte[] k)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(string k)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
#nullable disable
        internal SymmetricJwk(JwtObject @object)
#nullable enable
        {
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                var name = property.Utf8Name;
                switch (property.Type)
                {
                    case JwtTokenType.Array:
                        Populate(name, (JwtArray)property.Value!);
                        break;
                    case JwtTokenType.String:
                        if (name.SequenceEqual(JwkParameterNames.KUtf8))
                        {
                            _k = Base64Url.Decode((string)property.Value!);
                        }
                        else
                        {
                            Populate(name, (string)property.Value!);
                        }
                        break;
                    case JwtTokenType.Utf8String:
                        Populate(name, (byte[])property.Value!);
                        break;
                    default:
                        break;
                }
            }

            if (_k is null)
            {
                ThrowHelper.ThrowFormatException_MalformedJson("Missing 'k' property.");
            }
        }

        internal SymmetricJwk(ref Utf8JsonReader reader)
        {
            byte[]? k = null;
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        PopulateObject(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        PopulateArray(ref reader, ref propertyNameRef, propertyName.Length, this);
                        break;
                    case JsonTokenType.String:
                        switch (propertyName.Length)
                        {
                            case 1 when propertyNameRef == (byte)'k':
                                k = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                break;

                            case 3:
                                PopulateThree(ref reader, ref propertyNameRef, this);
                                break;
                            case 8:
                                PopulateEight(ref reader, ref propertyNameRef, this);
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (k is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(byte[] k, SignatureAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(string k, SignatureAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(byte[] k, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(string k, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.Octet;

        /// <summary>
        /// Gets or sets the 'k' (Key Value).
        /// </summary>
        public ReadOnlySpan<byte> K => _k;

        /// <inheritsdoc />
        public override int KeySizeInBits => _k.Length != 0 ? _k.Length << 3 : 0;

        /// <summary>
        /// Creates a new <see cref="SymmetricJwk"/> from the <paramref name="bytes"/>.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static SymmetricJwk FromByteArray(byte[] bytes) => FromByteArray(bytes, computeThumbprint: false);

        internal byte[] ToArray()
        {
            return _k;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        /// <param name="computeThumbprint"></param>
        public static SymmetricJwk FromByteArray(byte[] bytes, bool computeThumbprint)
        {
            if (bytes is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = Utf8.GetString(key.ComputeThumbprint());
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static SymmetricJwk FromSpan(ReadOnlySpan<byte> bytes) => FromSpan(bytes, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromSpan(ReadOnlySpan<byte> bytes, bool computeThumbprint)
        {
            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = Utf8.GetString(key.ComputeThumbprint());
            }

            return key;
        }

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
        {
            return ((algorithm.Category & AlgorithmCategory.Aes) != 0 && algorithm.RequiredKeySizeInBits == KeySizeInBits) || (algorithm == KeyManagementAlgorithm.Direct);
        }

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Hmac;
        }

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm)
        {
            return (algorithm.Category == EncryptionType.AesHmac || algorithm.Category == EncryptionType.AesGcm) && KeySizeInBits >= algorithm.RequiredKeySizeInBits;
        }

        /// <inheritdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
        {
            return new SymmetricSigner(this, algorithm);
        }

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (algorithm.Category == AlgorithmCategory.Aes)
            {
                return new AesKeyWrapper(this, encryptionAlgorithm, algorithm);
            }
            else if (algorithm.Category == AlgorithmCategory.AesGcm)
            {
                return new AesGcmKeyWrapper(this, encryptionAlgorithm, algorithm);
            }
            else if (!algorithm.ProduceEncryptionKey)
            {
                return new DirectKeyWrapper(this, encryptionAlgorithm, algorithm);
            }

            ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            return null;
        }

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (algorithm.Category == AlgorithmCategory.Aes)
            {
                return new AesKeyUnwrapper(this, encryptionAlgorithm, algorithm);
            }
            else if (algorithm.Category == AlgorithmCategory.AesGcm)
            {
                return new AesGcmKeyUnwrapper(this, encryptionAlgorithm, algorithm);
            }
            else if (!algorithm.ProduceEncryptionKey)
            {
                return new DirectKeyUnwrapper(this, encryptionAlgorithm, algorithm);
            }

            ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            return null;
        }

        /// <inheritsdoc />
        protected override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category == EncryptionType.AesHmac)
            {
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
                if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
                {
                    if (encryptionAlgorithm == EncryptionAlgorithm.Aes128CbcHmacSha256)
                    {
                        return new AesCbcHmacEncryptor(_k.AsSpan(0, 16), encryptionAlgorithm, new AesNiCbc128Encryptor(_k.AsSpan(16)));
                    }
                    else if (encryptionAlgorithm == EncryptionAlgorithm.Aes256CbcHmacSha512)
                    {
                        return new AesCbcHmacEncryptor(_k.AsSpan(0, 32), encryptionAlgorithm, new AesNiCbc256Encryptor(_k.AsSpan(32)));
                    }
                    else if (encryptionAlgorithm == EncryptionAlgorithm.Aes192CbcHmacSha384)
                    {
                        return new AesCbcHmacEncryptor(_k.AsSpan(0, 24), encryptionAlgorithm, new AesNiCbc192Encryptor(_k.AsSpan(24)));
                    }
                }
                else
                {
                    return new AesCbcHmacEncryptor(this, encryptionAlgorithm);
                }
#else
                return new AesCbcHmacEncryptor(this, encryptionAlgorithm);
#endif
            }
            else if (encryptionAlgorithm.Category == EncryptionType.AesGcm)
            {
                return new AesGcmEncryptor(this, encryptionAlgorithm);
            }

            ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            return null;
        }

        /// <inheritsdoc />
        protected override AuthenticatedDecryptor CreateAuthenticatedDecryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category == EncryptionType.AesHmac)
            {
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
                if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
                {
                    if (encryptionAlgorithm == EncryptionAlgorithm.Aes128CbcHmacSha256)
                    {
                        return new AesCbcHmacDecryptor(_k.AsSpan(0, 16), encryptionAlgorithm, new AesNiCbc128Decryptor(_k.AsSpan(16)));
                    }
                    else if (encryptionAlgorithm == EncryptionAlgorithm.Aes256CbcHmacSha512)
                    {
                        return new AesCbcHmacDecryptor(_k.AsSpan(0, 32), encryptionAlgorithm, new AesNiCbc256Decryptor(_k.AsSpan(32)));
                    }
                    else if (encryptionAlgorithm == EncryptionAlgorithm.Aes192CbcHmacSha384)
                    {
                        return new AesCbcHmacDecryptor(_k.AsSpan(0, 24), encryptionAlgorithm, new AesNiCbc192Decryptor(_k.AsSpan(24)));
                    }
                }
                else
                {
                    return new AesCbcHmacDecryptor(this, encryptionAlgorithm);
                }
#else
                return new AesCbcHmacDecryptor(this, encryptionAlgorithm);
#endif
            }
            else if (encryptionAlgorithm.Category == EncryptionType.AesGcm)
            {
                return new AesGcmDecryptor(this, encryptionAlgorithm);
            }

            ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            return null;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k"></param>
        /// <returns></returns>
        public static SymmetricJwk FromBase64Url(string k) => FromBase64Url(k, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromBase64Url(string k, bool computeThumbprint)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            var key = new SymmetricJwk(k);
            if (computeThumbprint)
            {
                key.Kid = Utf8.GetString(key.ComputeThumbprint());
            }

            return key;
        }

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits) => GenerateKey(sizeInBits, algorithm: (byte[]?)null);

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits, byte[]? algorithm)
        {
            var key = FromByteArray(GenerateKeyBytes(sizeInBits), false);
            if (!(algorithm is null))
            {
                key.Alg = algorithm;
            }

            return key;
        }

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits, SignatureAlgorithm algorithm)
                  => GenerateKey(sizeInBits, algorithm?.Utf8Name);

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits, KeyManagementAlgorithm algorithm)
            => GenerateKey(sizeInBits, algorithm?.Utf8Name);

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            byte[] key = new byte[sizeInBits >> 3];
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            RandomNumberGenerator.Fill(key);
#else
            _randomNumberGenerator.GetBytes(key);
#endif
            return key;
        }

        /// <inheritdoc />      
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            writer.WriteStartObject();
            writer.WriteString(JwkParameterNames.KUtf8, Base64Url.Encode(_k));
            writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
            writer.WriteEndObject();
            writer.Flush();
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            return _k;
        }

        /// <inheritdoc />      
        public override void WriteTo(Utf8JsonWriter writer)
        {
            base.WriteTo(writer);
            writer.WriteString(JwkParameterNames.KUtf8, Base64Url.Encode(_k));
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (!(other is SymmetricJwk key))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return _k.AsSpan().SequenceEqual(key._k);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            unchecked
            {
                var k = _k;
                if (k.Length >= sizeof(int))
                {
                    return Unsafe.ReadUnaligned<int>(ref k[0]);
                }
                else
                {
                    int hash = (int)2166136261;
                    for (int i = 0; i < k.Length; i++)
                    {
                        hash = (hash ^ k[i]) * 16777619;
                    }

                    return hash;
                }
            }
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_k != null)
            {
                CryptographicOperations.ZeroMemory(_k);
            }
        }
    }
}