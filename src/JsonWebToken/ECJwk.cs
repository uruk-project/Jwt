// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents an Elliptic Curve JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class ECJwk : AsymmetricJwk
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        public ECJwk(ECParameters parameters)
        {
            parameters.Validate();

            D = parameters.D;
            X = parameters.Q.X;
            Y = parameters.Q.Y;
            switch (parameters.Curve.Oid.FriendlyName)
            {
                case "nistP256":
                case "ECDSA_P256":
                    Crv = EllipticalCurves.P256;
                    break;
                case "nistP384":
                case "ECDSA_P384":
                    Crv = EllipticalCurves.P384;
                    break;
                case "nistP521":
                case "ECDSA_P521":
                    Crv = EllipticalCurves.P521;
                    break;
                default:
                    Errors.ThrowNotSupportedCurve(parameters.Curve.Oid.FriendlyName);
                    break;
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(string crv, byte[] d, byte[] x, byte[] y)
        {
            if (d == null)
            {
                throw new ArgumentNullException(nameof(d));
            }

            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv ?? throw new ArgumentNullException(nameof(crv));
            D = CloneByteArray(d);
            X = CloneByteArray(x);
            Y = CloneByteArray(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(string crv, string d, string x, string y)
        {
            if (d == null)
            {
                throw new ArgumentNullException(nameof(d));
            }

            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv ?? throw new ArgumentNullException(nameof(crv));
            D = Base64Url.Base64UrlDecode(d);
            X = Base64Url.Base64UrlDecode(x);
            Y = Base64Url.Base64UrlDecode(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(string crv, byte[] x, byte[] y)
        {
            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv ?? throw new ArgumentNullException(nameof(crv));
            X = CloneByteArray(x);
            Y = CloneByteArray(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(string crv, string x, string y)
        {
            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv ?? throw new ArgumentNullException(nameof(crv));
            X = Base64Url.Base64UrlDecode(x);
            Y = Base64Url.Base64UrlDecode(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk()
        {
        }

        /// <inheritsdoc />
        public override string Kty => JwkTypeNames.EllipticCurve;

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Crv, Required = Required.Default)]
        public string Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] X { get; set; }

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Y, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Y { get; set; }

        /// <inheritdoc />
        public override bool HasPrivateKey => D != null;

        /// <inheritdoc />
        public override int KeySizeInBits
        {
            get
            {
                switch (Crv)
                {
                    case EllipticalCurves.P256:
                        return 256;
                    case EllipticalCurves.P384:
                        return 384;
                    case EllipticalCurves.P521:
                        return 521;
                    default:
                        Errors.ThrowNotSupportedCurve(Crv);
                        return 0;
                }
            }
        }

        /// <summary>
        /// Creates an <see cref="ECDsa"/> algorithm.
        /// </summary>
        public ECDsa CreateECDsa(SignatureAlgorithm algorithm, bool usePrivateKey)
        {
            int validKeySize = ValidKeySize(algorithm);
            if (KeySizeInBits != validKeySize)
            {
                Errors.ThrowInvalidEcdsaKeySize(this, algorithm, validKeySize, KeySizeInBits);
            }

            return ECDsa.Create(ExportParameters(usePrivateKey));
        }

        private static int ValidKeySize(SignatureAlgorithm algorithm)
        {
            return algorithm.RequiredKeySizeInBits;
        }

        /// <inheritdoc />
        public override bool IsSupported(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.EllipticCurve;
        }

        /// <inheritdoc />
        public override bool IsSupported(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.EllipticCurve;
        }

        /// <inheritdoc />
        public override bool IsSupported(EncryptionAlgorithm algorithm)
        {
#if NETCOREAPP3_0
            return algorithm.Category == EncryptionType.AesHmac || algorithm.Category == EncryptionType.AesGcm;
#else
            return algorithm.Category == EncryptionType.AesHmac;
#endif
        }

        /// <inheritdoc />
        public override Signer CreateSigner(SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm is null)
            {
                return null;
            }

            if (IsSupported(algorithm))
            {
                return new EcdsaSigner(this, algorithm, willCreateSignatures);
            }

            return null;
        }

        /// <inheritdoc />
        public override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
#if !NETSTANDARD2_0
            return new EcdhKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
#else
            return null;
#endif
        }

        /// <summary>
        /// Exports the key parameters.
        /// </summary>
        public ECParameters ExportParameters() => ExportParameters(false);

        /// <summary>
        /// Exports the key parameters.
        /// </summary>
        public ECParameters ExportParameters(bool includePrivateParameters)
        {
            var parameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = X,
                    Y = Y
                }
            };
            if (includePrivateParameters)
            {
                parameters.D = D;
            }

            switch (Crv)
            {
                case EllipticalCurves.P256:
                    parameters.Curve = ECCurve.NamedCurves.nistP256;
                    break;
                case EllipticalCurves.P384:
                    parameters.Curve = ECCurve.NamedCurves.nistP384;
                    break;
                case EllipticalCurves.P521:
                    parameters.Curve = ECCurve.NamedCurves.nistP521;
                    break;
                default:
                    Errors.ThrowNotSupportedCurve(Crv);
                    break;
            }

            return parameters;
        }

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curveId"></param>
        /// <param name="withPrivateKey"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(string curveId, bool withPrivateKey) => GenerateKey(curveId, withPrivateKey, algorithm: null);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curveId"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(string curveId, bool withPrivateKey, string algorithm)
        {
            if (string.IsNullOrEmpty(curveId))
            {
                throw new ArgumentNullException(nameof(curveId));
            }

            ECCurve curve = default;
            switch (curveId)
            {
                case EllipticalCurves.P256:
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
                case EllipticalCurves.P384:
                    curve = ECCurve.NamedCurves.nistP384;
                    break;
                case EllipticalCurves.P521:
                    curve = ECCurve.NamedCurves.nistP521;
                    break;
                default:
                    Errors.ThrowNotSupportedCurve(curveId);
                    break;
            }

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.GenerateKey(curve);
                var parameters = ecdsa.ExportParameters(withPrivateKey);
                return FromParameters(parameters, algorithm);
            }
        }

        /// <inheritdoc />
        public override Jwk Canonicalize()
        {
            return new ECJwk(Crv, D, X, Y);
        }

        internal static ECJwk FromDictionary(Dictionary<string, object> jObject)
        {
            if (jObject == null)
            {
                return null;
            }

            var key = new ECJwk();
            if (jObject.TryGetValue("crv", out object crv))
            {
                key.Crv = (string)crv;
            }

            if (jObject.TryGetValue("x", out object x))
            {
                key.X = Base64Url.Base64UrlDecode((string)x);
            }

            if (jObject.TryGetValue("y", out object y))
            {
                key.Y = Base64Url.Base64UrlDecode((string)y);
            }

            if (jObject.TryGetValue("d", out object d))
            {
                key.D = Base64Url.Base64UrlDecode((string)d);
            }

            return key;
        }

//#if NETCOREAPP3_0
        internal static unsafe ECJwk FromJsonReader(ref Utf8JsonReader reader)
        {
            var key = new ECJwk();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        ReadOnlySpan<byte> valueSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        switch (valueSpan.Length)
                        {
                            case 1:
                                byte value = valueSpan[0];
                                if (value == 120 /* 'x' */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.X = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        JwtThrowHelper.FormatMalformedJson(JwkParameterNames.X, JsonTokenType.String);
                                    }
                                }
                                else if (value == 121 /* 'y' */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.Y = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        JwtThrowHelper.FormatMalformedJson(JwkParameterNames.Y, JsonTokenType.String);
                                    }
                                }
                                else if (value == 100 /* 'd' */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.D = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        JwtThrowHelper.FormatMalformedJson(JwkParameterNames.D, JsonTokenType.String);
                                    }
                                }
                                else
                                {
                                    break;
                                }
                                break;
                            case 3:
                                fixed (byte* pPropertyByte = valueSpan)
                                {
                                    uint property = (uint)(((*(ushort*)pPropertyByte) << 8) | *(pPropertyByte + 2));

                                    if (property == 7496566u /* 'crv' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            key.Crv = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(JwkParameterNames.Crv, JsonTokenType.String);
                                        }
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                                break;
                            default:
                                break;
                        }

                        break;

                    default:
                        break;
                }
            }

            return key;
        }
//#endif

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, string algorithm, bool computeThumbprint)
        {
            var key = new ECJwk(parameters);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            if (algorithm != null)
            {
                key.Alg = algorithm;
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters) => FromParameters(parameters, null, false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, string algorithm) => FromParameters(parameters, algorithm, false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, bool computeThumbprint) => FromParameters(parameters, null, computeThumbprint);

        /// <inheritdoc />
        public override byte[] ToByteArray()
        {
#if !NETSTANDARD2_0
            using (var ecdh = ECDiffieHellman.Create(ExportParameters()))
            {
                return ecdh.PublicKey.ToByteArray();
            }
#else
            throw new NotImplementedException();
#endif
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        internal static ECJwk FromJwtObject(JwtObject jwtObject)
        {
            Debug.Assert(jwtObject.Count == 3);
            var key = new ECJwk
            {
                Y = Base64Url.Base64UrlDecode((byte[])jwtObject[2].Value),
                X = Base64Url.Base64UrlDecode((byte[])jwtObject[1].Value),
                Crv = (string)jwtObject[0].Value
            };


            return key;
        }

        internal JwtObject AsJwtObject()
        {
            var jwtObject = new JwtObject();
            jwtObject.Add(new JwtProperty(JwkParameterNames.CrvUtf8, Crv));
            jwtObject.Add(new JwtProperty(JwkParameterNames.XUtf8, Base64Url.Base64UrlEncode(X)));
            jwtObject.Add(new JwtProperty(JwkParameterNames.YUtf8, Base64Url.Base64UrlEncode(Y)));

            return jwtObject;
        }
    }
}