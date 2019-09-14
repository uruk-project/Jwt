// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a symmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class SymmetricJwk : Jwk
    {
        private readonly byte[] _k;

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
        public SymmetricJwk(string k)
        {
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            _k = Base64Url.Decode(k);
        }

#nullable disable
        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
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

            _k = k!; // ! => [DoesNotReturn]
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

            _k = k!; // ! => [DoesNotReturn]
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

            _k = Base64Url.Decode(k!); // ! => [DoesNotReturn]
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

            _k = k!; // ! => [DoesNotReturn]
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

            _k = Base64Url.Decode(k!); // ! => [DoesNotReturn]
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
        /// Gets or sets whether the key is ephemeral, and should not try to reuse internal objects.
        /// </summary>
        public bool Ephemeral { get; set; }

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

            var key = new SymmetricJwk(bytes!); // ! => [DoesNotReturn]
            if (computeThumbprint)
            {
                key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
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
            var key = new SymmetricJwk(bytes.ToArray());
            if (computeThumbprint)
            {
                key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
            }

            return key;
        }

        /// <inheritsdoc />
        public override bool IsSupported(KeyManagementAlgorithm algorithm)
        {
            return ((algorithm.Category & AlgorithmCategory.Aes) != 0 && algorithm.RequiredKeySizeInBits == KeySizeInBits) || (algorithm == KeyManagementAlgorithm.Direct);
        }

        /// <inheritsdoc />
        public override bool IsSupported(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Hmac;
        }

        /// <inheritsdoc />
        public override bool IsSupported(EncryptionAlgorithm algorithm)
        {
            return algorithm.Category == EncryptionType.AesHmac || algorithm.Category == EncryptionType.AesGcm;
        }

        /// <inheritdoc />
        protected override Signer CreateNewSigner(SignatureAlgorithm algorithm)
        {
            return new SymmetricSigner(this, algorithm);
        }

        /// <inheritsdoc />
        protected override KeyWrapper? CreateNewKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
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

            return null;
        }

        /// <inheritsdoc />
        protected override AuthenticatedEncryptor? CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category == EncryptionType.AesHmac)
            {
                if (KeySizeInBits >= encryptionAlgorithm.RequiredKeySizeInBits)
                {
                    return new AesCbcHmacEncryptor(this, encryptionAlgorithm);
                }
            }
            else if (encryptionAlgorithm.Category == EncryptionType.AesGcm)
            {
                if (KeySizeInBits >= encryptionAlgorithm.RequiredKeySizeInBits)
                {
                    return new AesGcmEncryptor(this, encryptionAlgorithm);
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
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            var key = new SymmetricJwk(k!);
            if (computeThumbprint)
            {
                key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
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
            using (var rnd = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[sizeInBits >> 3];
                rnd.GetBytes(key);

                return key;
            }
        }

        /// <inheritdoc />      
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using (var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation))
            {
                writer.WriteStartObject();
                writer.WriteString(JwkParameterNames.KUtf8, Base64Url.Encode(_k));
                writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
                writer.WriteEndObject();
                writer.Flush();
            }
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            return _k;
        }

        internal override void WriteComplementTo(Utf8JsonWriter writer)
        {
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