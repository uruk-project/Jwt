// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a symmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class SymmetricJwk : Jwk
    {
        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(byte[] k)
        {
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            K = CloneByteArray(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk(ReadOnlySpan<byte> k)
        {
            K = k.ToArray();
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

            K = Base64Url.Base64UrlDecode(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        public SymmetricJwk()
        {
        }

        //internal SymmetricJwk(JwkInfo info)
        //{
        //    throw new NotImplementedException();
        //}

        /// <inheritsdoc />
        public override string Kty => JwkTypeNames.Octet;

        /// <summary>
        /// Gets or sets the 'k' (Key Value).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.K, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] K { get; set; }

        /// <inheritsdoc />
        public override int KeySizeInBits => K?.Length != 0 ? K.Length << 3 : 0;

        /// <summary>
        /// Creates a new <see cref="SymmetricJwk"/> from the <paramref name="bytes"/>.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static SymmetricJwk FromByteArray(byte[] bytes) => FromByteArray(bytes, computeThumbprint: false);

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
                key.Kid = key.ComputeThumbprint(false);
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
                key.Kid = key.ComputeThumbprint(false);
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
                key.Kid = key.ComputeThumbprint(false);
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

        /// <inheritsdoc />
        public override Jwk Canonicalize()
        {
            return new SymmetricJwk(K);
        }

        /// <inheritsdoc />
        public override byte[] ToByteArray()
        {
            return K;
        }
    }
}