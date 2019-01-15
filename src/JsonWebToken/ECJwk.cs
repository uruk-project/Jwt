// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Represents an Elliptic Curve JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class ECJwk : AsymmetricJwk
    {
        private string _x;
        private string _y;

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        public ECJwk(ECParameters parameters)
            : this()
        {
            parameters.Validate();

            RawD = parameters.D;
            RawX = parameters.Q.X;
            RawY = parameters.Q.Y;
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

        private ECJwk(string crv, byte[] d, byte[] x, byte[] y)
        {
            Crv = crv;
            RawD = CloneByteArray(d);
            RawX = CloneByteArray(x);
            RawY = CloneByteArray(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk()
        {
            Kty = JwkTypeNames.EllipticCurve;
        }

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Crv, Required = Required.Default)]
        public string Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X, Required = Required.Default)]
        public string X
        {
            get
            {
                if (_x == null)
                {
                    if (RawX != null && RawX.Length != 0)
                    {
                        _x = Base64Url.Base64UrlEncode(RawX);
                    }
                }

                return _x;
            }
            set
            {
                _x = value;
                if (value != null)
                {
                    RawX = Base64Url.Base64UrlDecode(value);
                }
                else
                {
                    RawX = null;
                }
            }
        }

        /// <summary>
        /// Gets the 'x' represented in array of bytes.
        /// </summary>
        [JsonIgnore]
        public byte[] RawX { get; private set; }

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Y, Required = Required.Default)]
        public string Y
        {
            get
            {
                if (_y == null)
                {
                    if (RawY != null && RawY.Length != 0)
                    {
                        _y = Base64Url.Base64UrlEncode(RawY);
                    }
                }

                return _y;
            }
            set
            {
                _y = value;
                if (value != null)
                {
                    RawY = Base64Url.Base64UrlDecode(value);
                }
                else
                {
                    RawY = null;
                }
            }
        }

        /// <summary>
        /// Gets the 'y' represented in array of bytes.
        /// </summary>
        [JsonIgnore]
        public byte[] RawY { get; private set; }

        /// <inheritdoc />
        public override bool HasPrivateKey => RawD != null;

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
                    X = RawX,
                    Y = RawY
                }
            };
            if (includePrivateParameters)
            {
                parameters.D = RawD;
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
            return new ECJwk(Crv, RawD, RawX, RawY);
        }

        internal static ECJwk FromJObject(JObject jObject)
        {
            if (jObject == null)
            {
                return null;
            }

            var key = new ECJwk
            {
                Crv = jObject[JwkParameterNames.Crv].Value<string>(),
                X = jObject[JwkParameterNames.X]?.Value<string>(),
                Y = jObject[JwkParameterNames.Y]?.Value<string>(),
                D = jObject[JwkParameterNames.D]?.Value<string>()
            };

            return key;
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
                key.X = (string)x;
            }

            if (jObject.TryGetValue("y", out object y))
            {
                key.Y = (string)y;
            }

            if (jObject.TryGetValue("d", out object d))
            {
                key.D = (string)d;
            }

            return key;
        }

#if NETCOREAPP3_0
        internal static unsafe ECJwk FromJsonReader(Utf8JsonReader reader)
        {
            var key = new ECJwk();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        ReadOnlySpan<byte> valueSpan = reader.ValueSpan;
                        switch (valueSpan.Length)
                        {
                            case 1:
                                byte value = valueSpan[0];
                                if (value == 120 /* "x" */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.RawX = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        ThrowHelper.FormatMalformedJson(JwkParameterNames.X, JsonTokenType.String);
                                    }
                                }
                                else if (value == 121 /* "y" */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.RawY = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        ThrowHelper.FormatMalformedJson(JwkParameterNames.Y, JsonTokenType.String);
                                    }
                                }
                                else if (value == 100 /* "d" */)
                                {
                                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        key.RawD = Base64Url.Base64UrlDecode(reader.ValueSpan);
                                    }
                                    else if (reader.TokenType != JsonTokenType.Null)
                                    {
                                        ThrowHelper.FormatMalformedJson(JwkParameterNames.D, JsonTokenType.String);
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

                                    // 'crv' = { 99, 114, 118 };
                                    if (property == 7496566u)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            key.Crv = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.Crv, JsonTokenType.String);
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
#endif

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
    }
}