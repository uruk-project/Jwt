// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a symmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class SymmetricJwk : Jwk
    {
        private byte[] _k;

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(byte[] k)
        {
            _k = k ?? throw new ArgumentNullException(nameof(k));
        }

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
        public SymmetricJwk(string k)
        {
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            _k = Base64Url.Base64UrlDecode(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk()
        {
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.Octet;

        /// <summary>
        /// Gets or sets the 'k' (Key Value).
        /// </summary>
        public ReadOnlySpan<byte> K => _k;

        /// <inheritsdoc />
        public override int KeySizeInBits => K.Length != 0 ? K.Length << 3 : 0;

        private void SetKeyValue(byte[] k)
        {
            _k = k;
        }

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
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint();
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
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint();
            }

            return key;
        }

        /// <inheritsdoc />
        public override bool IsSupported(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Aes && algorithm.RequiredKeySizeInBits == KeySizeInBits;
        }

        /// <inheritsdoc />
        public override bool IsSupported(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Hmac;
        }

        /// <inheritsdoc />
        public override bool IsSupported(EncryptionAlgorithm algorithm)
        {
            return algorithm.Category == EncryptionType.AesHmac;
        }

        /// <inheritsdoc />
        public override Signer CreateSigner(SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm is null)
            {
                return null;
            }

            if (IsSupported(algorithm))
            {
                return new SymmetricSigner(this, algorithm);
            }

            return null;
        }

        /// <inheritsdoc />
        public override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm is null)
            {
                return null;
            }

            if (IsSupported(contentEncryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionType.AesHmac:
                        return new AesKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
#if NETCOREAPP3_0
                    case EncryptionType.AesGcm:
                        return new AesGcmKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
#endif
                    default:
                        return null;
                }
            }

            return null;
        }

        /// <inheritsdoc />
        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (IsSupported(encryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionType.None:
                        break;
                    case EncryptionType.AesHmac:
                        return new AesCbcHmacEncryptor(this, encryptionAlgorithm);
#if NETCOREAPP3_0
                    case EncryptionType.AesGcm:
                        return new AesGcmEncryptor(this, encryptionAlgorithm);
#endif
                    default:
                        return null;
                }
            }

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
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            var key = new SymmetricJwk(k);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint();
            }

            return key;
        }

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits) => GenerateKey(sizeInBits, algorithm: null);

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits, string algorithm)
        {
            var key = FromByteArray(GenerateKeyBytes(sizeInBits), false);
            if (algorithm != null)
            {
                key.Alg = algorithm;
            }

            return key;
        }

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[sizeInBits >> 3];
                rnd.GetBytes(key);

                return key;
            }
        }

        internal unsafe static Jwk FromJsonReaderFast(ref Utf8JsonReader reader)
        {
            var key = new SymmetricJwk();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:

                        var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        fixed (byte* pPropertyName = propertyName)
                        {
                            reader.Read();
                            switch (reader.TokenType)
                            {
                                case JsonTokenType.StartObject:
                                    PopulateObject(ref reader, pPropertyName, propertyName.Length, key);
                                    break;
                                case JsonTokenType.StartArray:
                                    PopulateArray(ref reader, pPropertyName, propertyName.Length, key);
                                    break;
                                case JsonTokenType.String:
                                    switch (propertyName.Length)
                                    {
                                        case 1:
                                            if (*pPropertyName == (byte)'k')
                                            {
                                                key._k = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                            }
                                            break;

                                        case 3:
                                            PopulateThree(ref reader, pPropertyName, key);
                                            break;
                                        case 8:
                                            PopulateEight(ref reader, pPropertyName, key);
                                            break;
                                        default:
                                            break;
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                        break;
                    case JsonTokenType.EndObject:
                        return key;
                    default:
                        break;
                }
            }

            Errors.ThrowMalformedKey();
            return null;
        }

        /// <inheritdoc />
        public override byte[] Canonicalize()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = false, SkipValidation = true }));
                writer.WriteStartObject();
                writer.WriteString(JwkParameterNames.KUtf8, Base64Url.Base64UrlEncode(K));
                writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
                writer.WriteEndObject();
                writer.Flush();

                return bufferWriter.WrittenSpan.ToArray();
            }
        }

        /// <inheritsdoc />
        public override byte[] ToByteArray()
        {
            return _k;
        }

        internal static SymmetricJwk Populate(JwtObject @object)
        {
            var key = new SymmetricJwk();
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                var name = property.Utf8Name.Span;
                switch (property.Type)
                {
                    case JwtTokenType.Array:
                        key.Populate(name, (JwtArray)property.Value);
                        break;
                    case JwtTokenType.String:
                        if (name.SequenceEqual(JwkParameterNames.KUtf8))
                        {
                            key._k = Base64Url.Base64UrlDecode((string)property.Value);
                        }
                        else
                        {
                            key.Populate(name, (string)property.Value);
                        }
                        break;
                    default:
                        break;
                }
            }

            return key;
        }

        internal override void WriteComplementTo(ref Utf8JsonWriter writer)
        {
            writer.WriteString(JwkParameterNames.KUtf8, Base64Url.Base64UrlEncode(K));
        }
    }
}