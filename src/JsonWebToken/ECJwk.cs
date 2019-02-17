// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
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
                    Crv = EllipticalCurve.P256;
                    break;
                case "nistP384":
                case "ECDSA_P384":
                    Crv = EllipticalCurve.P384;
                    break;
                case "nistP521":
                case "ECDSA_P521":
                    Crv = EllipticalCurve.P521;
                    break;
                default:
                    Errors.ThrowNotSupportedCurve(parameters.Curve.Oid.FriendlyName);
                    break;
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y)
        {
            Crv = crv;
            D = d ?? throw new ArgumentNullException(nameof(d));
            X = x ?? throw new ArgumentNullException(nameof(x));
            Y = y ?? throw new ArgumentNullException(nameof(y));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string d, string x, string y)
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

            Crv = crv;
            D = Base64Url.Base64UrlDecode(d);
            X = Base64Url.Base64UrlDecode(x);
            Y = Base64Url.Base64UrlDecode(y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] x, byte[] y)
        {
            Crv = crv;
            X = x ?? throw new ArgumentNullException(nameof(x));
            Y = y ?? throw new ArgumentNullException(nameof(y));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string x, string y)
        {
            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv;
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
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.EllipticCurve;

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        public EllipticalCurve Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        public byte[] X { get; set; }

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        public byte[] Y { get; set; }

        /// <inheritdoc />
        public override bool HasPrivateKey => D != null;

        /// <inheritdoc />
        public override int KeySizeInBits => Crv.KeySizeInBits;

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
                },
                Curve = Crv.CurveParameters
            };
            if (includePrivateParameters)
            {
                parameters.D = D;
            }

            return parameters;
        }

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey) => GenerateKey(curve, withPrivateKey, algorithm: null);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, string algorithm)
        {
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.GenerateKey(curve.CurveParameters);
                var parameters = ecdsa.ExportParameters(withPrivateKey);
                return FromParameters(parameters, algorithm);
            }
        }

        /// <inheritdoc />
        public override byte[] Canonicalize()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = false, SkipValidation = true }));
                writer.WriteStartObject();
                writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);
                writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
                writer.WriteString(JwkParameterNames.XUtf8, Base64Url.Base64UrlEncode(X));
                writer.WriteString(JwkParameterNames.YUtf8, Base64Url.Base64UrlEncode(Y));
                writer.WriteEndObject();
                writer.Flush();

                return bufferWriter.WrittenSpan.ToArray();
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, KeyManagementAlgorithm algorithm, bool computeThumbprint)
        {
            return FromParameters(parameters, algorithm.Utf8Name, computeThumbprint);
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, SignatureAlgorithm algorithm, bool computeThumbprint)
        {
            return FromParameters(parameters, algorithm.Name, computeThumbprint);
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, string algorithm, bool computeThumbprint)
        {
            return FromParameters(parameters, Encoding.UTF8.GetBytes(algorithm), computeThumbprint);
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, byte[] algorithm, bool computeThumbprint)
        {
            var key = new ECJwk(parameters);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint();
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
        public static ECJwk FromParameters(ECParameters parameters) => FromParameters(parameters, (byte[])null, false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, string algorithm) => FromParameters(parameters, algorithm, false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, bool computeThumbprint) => FromParameters(parameters, (byte[])null, computeThumbprint);

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
                Y = Base64Url.Base64UrlDecode(jwtObject.TryGetValue(JwkParameterNames.YUtf8, out var property) ? (string)property.Value : null),
                X = Base64Url.Base64UrlDecode(jwtObject.TryGetValue(JwkParameterNames.XUtf8, out property) ? (string)property.Value : null),
                Crv = EllipticalCurve.FromString(jwtObject.TryGetValue(JwkParameterNames.CrvUtf8, out property) ? (string)property.Value : null)
            };


            return key;
        }

        internal JwtObject AsJwtObject()
        {
            var jwtObject = new JwtObject();
            jwtObject.Add(new JwtProperty(JwkParameterNames.CrvUtf8, Crv.Name));
            jwtObject.Add(new JwtProperty(JwkParameterNames.XUtf8, Base64Url.Base64UrlEncode(X)));
            jwtObject.Add(new JwtProperty(JwkParameterNames.YUtf8, Base64Url.Base64UrlEncode(Y)));

            return jwtObject;
        }

        internal unsafe static Jwk FromJsonReaderFast(ref Utf8JsonReader reader)
        {
            var key = new ECJwk();

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
                                            if (*pPropertyName == (byte)'x')
                                            {
                                                key.X = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                            }
                                            else if (*pPropertyName == (byte)'y')
                                            {
                                                key.Y = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                            }
                                            else if (*pPropertyName == (byte)'d')
                                            {
                                                key.D = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                            }
                                            break;

                                        case 3:
                                            if (*pPropertyName == (byte)'c' && *((short*)pPropertyName + 1) == 30322)
                                            {
                                                key.Crv = EllipticalCurve.FromSpan(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                            }
                                            else
                                            {
                                                PopulateThree(ref reader, pPropertyName, key);
                                            }
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

        internal static ECJwk Populate(JwtObject @object)
        {
            var key = new ECJwk();
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
                        if (name.SequenceEqual(JwkParameterNames.CrvUtf8))
                        {
                            key.Crv = EllipticalCurve.FromString((string)property.Value);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.XUtf8))
                        {
                            key.X = Base64Url.Base64UrlDecode((string)property.Value);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.YUtf8))
                        {
                            key.Y = Base64Url.Base64UrlDecode((string)property.Value);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.DUtf8))
                        {
                            key.D = Base64Url.Base64UrlDecode((string)property.Value);
                        }
                        else
                        {
                            key.Populate(name, (string)property.Value);
                        }
                        break;
                    case JwtTokenType.Utf8String:
                        key.Populate(name, (byte[])property.Value);
                        break;
                    default:
                        break;
                }
            }

            return key;
        }

        internal override void WriteComplementTo(ref Utf8JsonWriter writer)
        {
            writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);
            writer.WriteString(JwkParameterNames.XUtf8, Base64Url.Base64UrlEncode(X));
            writer.WriteString(JwkParameterNames.YUtf8, Base64Url.Base64UrlEncode(Y));
            if (D != null)
            {
                writer.WriteString(JwkParameterNames.DUtf8, Base64Url.Base64UrlEncode(D));
            }
        }
    }
}