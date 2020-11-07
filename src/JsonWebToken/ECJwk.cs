// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
#nullable disable
    /// <summary>
    /// Represents an Elliptic Curve JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class ECJwk : AsymmetricJwk, IJwtSerializable
    {
        private const uint crv = 7762531u;
        private byte[] _x;
        private byte[] _y;

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        private ECJwk(ECParameters parameters)
        {
            Initialize(parameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y)
            : base(d)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y)
            : base(d)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] x, byte[] y)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string x, string y)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="alg"></param>
        private ECJwk(ECParameters parameters, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(parameters);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y, SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y, alg);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y, SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y, alg);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] x, byte[] y, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y, alg);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string x, string y, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y, alg);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="alg"></param>
        private ECJwk(ECParameters parameters, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(parameters);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y, KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y, KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, byte[] x, byte[] y, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string x, string y, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk()
        {
        }
#nullable enable

        private void Initialize(ECParameters parameters)
        {
            parameters.Validate();

            _d = parameters.D;
            _x = parameters.Q.X;
            _y = parameters.Q.Y;
            Crv = parameters.Curve.Oid.FriendlyName switch
            {
                "nistP256" => EllipticalCurve.P256,
                "ECDSA_P256" => EllipticalCurve.P256,
                "nistP384" => EllipticalCurve.P384,
                "ECDSA_P384" => EllipticalCurve.P384,
                "nistP521" => EllipticalCurve.P521,
                "ECDSA_P521" => EllipticalCurve.P521,
                _ => throw ThrowHelper.CreateNotSupportedException_Curve(parameters.Curve.Oid.FriendlyName)
            };
        }

        private void Initialize(in EllipticalCurve crv, string x, string y, SignatureAlgorithm alg)
        {
            if (crv.SupportedSignatureAlgorithm != alg)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, crv);
            }

            Initialize(crv, x, y);
        }

        private void Initialize(in EllipticalCurve crv, string x, string y)
        {
            if (x is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.x);
            }

            if (y is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.y);
            }

            Crv = crv;
            _x = Base64Url.Decode(x);
            _y = Base64Url.Decode(y);
        }

        private void Initialize(in EllipticalCurve crv, byte[] x, byte[] y, SignatureAlgorithm alg)
        {
            if (crv.SupportedSignatureAlgorithm != alg)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, crv);
            }

            Initialize(crv, x, y);
        }

        private void Initialize(in EllipticalCurve crv, byte[] x, byte[] y)
        {
            if (x is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.x);
            }

            if (y is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.y);
            }

            Crv = crv;
            _x = x;
            _y = y;
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.EllipticCurve;

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        public EllipticalCurve Crv { get; private set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        public ReadOnlySpan<byte> X => _x;

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        public ReadOnlySpan<byte> Y => _y;

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
                ThrowHelper.ThrowArgumentOutOfRangeException_InvalidEcdsaKeySize(this, algorithm, validKeySize, KeySizeInBits);
            }

            return ECDsa.Create(ExportParameters(usePrivateKey));
        }

        private static int ValidKeySize(SignatureAlgorithm algorithm)
        {
            return algorithm.RequiredKeySizeInBits;
        }

        /// <inheritdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_SIGNATURE
            return Crv.SupportedSignatureAlgorithm == algorithm;
            //return algorithm.Category == AlgorithmCategory.EllipticCurve 
            //    && algorithm.RequiredKeySizeInBits == KeySizeInBits
            //    ;
#else
            return false;
#endif
        }

        /// <inheritdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
            return (algorithm.Category & AlgorithmCategory.EllipticCurve) != 0;
#else
            return false;
#endif
        }

        /// <inheritdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm)
        {
            return false;
        }

        /// <inheritdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_SIGNATURE
            return new EcdsaSigner(this, algorithm);
#else
            throw new NotImplementedException();
#endif
        }

        /// <inheritdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
            return new EcdhKeyWrapper(this, encryptionAlgorithm, algorithm);
#else
            throw new NotImplementedException();
#endif
        }

        /// <inheritdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
            return new EcdhKeyUnwrapper(this, encryptionAlgorithm, algorithm);
#else
            throw new NotImplementedException();
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
                    X = _x,
                    Y = _y
                },
                Curve = Crv.CurveParameters
            };
            if (includePrivateParameters)
            {
                parameters.D = _d;
            }

            return parameters;
        }

        /// <summary>
        /// Generates a private <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePrivateKey(in EllipticalCurve curve, bool computeThumbprint = true)
            => GenerateKey(curve, true, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a public <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePublicKey(in EllipticalCurve curve, bool computeThumbprint = true)
            => GenerateKey(curve, false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, bool computeThumbprint = true)
        {
            ECParameters parameters = GenerateParameters(curve, withPrivateKey);
            return FromParameters(parameters, computeThumbprint: computeThumbprint);
        }

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, SignatureAlgorithm algorithm, bool computeThumbprint = true)
        {
            ECParameters parameters = GenerateParameters(curve, withPrivateKey);
            return FromParameters(parameters, algorithm, computeThumbprint: computeThumbprint);
        }

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
        {
            ECParameters parameters = GenerateParameters(curve, withPrivateKey);
            return FromParameters(parameters, algorithm, computeThumbprint: computeThumbprint);
        }

        private static ECParameters GenerateParameters(in EllipticalCurve curve, bool withPrivateKey)
        {
            using ECDsa ecdsa = ECDsa.Create();
            ecdsa.GenerateKey(curve.CurveParameters);
            return ecdsa.ExportParameters(withPrivateKey);
        }

        /// <inheritdoc />
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            writer.WriteStartObject();
            writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);
            writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
            Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(_x.Length)];
            Base64Url.Encode(X, buffer);
            writer.WriteString(JwkParameterNames.XUtf8, buffer);
            Base64Url.Encode(Y, buffer);
            writer.WriteString(JwkParameterNames.YUtf8, buffer);
            writer.WriteEndObject();
            writer.Flush();
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, KeyManagementAlgorithm algorithm)
            => FromParameters(parameters, algorithm, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, KeyManagementAlgorithm algorithm, bool computeThumbprint)
        {
            var key = new ECJwk(parameters, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, SignatureAlgorithm algorithm)
            => FromParameters(parameters, algorithm, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, SignatureAlgorithm algorithm, bool computeThumbprint)
        {
            var key = new ECJwk(parameters, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, string d, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, string d, SignatureAlgorithm alg, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y, alg: alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, string d, KeyManagementAlgorithm alg, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y, alg: alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, byte[] d, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, byte[] d, SignatureAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, SignatureAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, SignatureAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, byte[] d, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, d: d, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromBase64Url(in EllipticalCurve crv, string x, string y, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromByteArray(in EllipticalCurve crv, byte[] x, byte[] y, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
        {
            var key = new ECJwk(crv, x: x, y: y, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters)
            => FromParameters(parameters, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, bool computeThumbprint = true)
        {
            var key = new ECJwk(parameters);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <inheritdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        internal static ECJwk FromJwtObject(JwtObject jwtObject)
        {
            Debug.Assert(jwtObject.Count == 3);
            if (!jwtObject.TryGetProperty(JwkParameterNames.CrvUtf8, out var crv) || crv.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!jwtObject.TryGetProperty(JwkParameterNames.XUtf8, out var x) || x.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!jwtObject.TryGetProperty(JwkParameterNames.YUtf8, out var y) || y.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return new ECJwk(EllipticalCurve.FromString((string)crv.Value), (string)x.Value, (string)y.Value);
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        internal static ECJwk FromJsonElement(JsonElement json)
        {
            //Debug.Assert(json.Count == 3);
            if (!json.TryGetProperty(JwkParameterNames.CrvUtf8, out var crv) || crv.ValueKind is JsonValueKind.Null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!json.TryGetProperty(JwkParameterNames.XUtf8, out var x) || x.ValueKind is JsonValueKind.Null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!json.TryGetProperty(JwkParameterNames.YUtf8, out var y) || y.ValueKind is JsonValueKind.Null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return new ECJwk(EllipticalCurve.FromString(crv.GetString()!), x.GetString(), y.GetString());
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        internal static ECJwk FromJwtElement(JwtElement json)
        {
            var reader = new Utf8JsonReader(json.GetRawValue().Span);
            reader.Read();
            return FromJsonReaderFast(ref reader);
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="pem">A PEM-encoded key in PKCS1 (BEGIN EC PRIVATE KEY) or PKCS8 (BEGIN PUBLIC/PRIVATE KEY) format.</param>
        /// Support unencrypted PKCS#1 private EC key, unencrypted PKCS#8 public EC key and unencrypted PKCS#8 private EC key. 
        /// Unencrypted PKCS#1 public EC key is not supported.
        /// Password-protected key is not supported.
        public new static ECJwk FromPem(string pem)
        {
            Jwk jwk = Jwk.FromPem(pem);
            if (!(jwk is ECJwk ecJwk))
            {
                jwk.Dispose();
                ThrowHelper.ThrowInvalidOperationException_UnexpectedKeyType(jwk, Utf8.GetString(JwkTypeNames.EllipticCurve));
                return null;
            }

            return ecJwk;
        }

        internal JwtObject AsJwtObject()
        {
            var jwtObject = new JwtObject
            {
                new JwtProperty(JwkParameterNames.CrvUtf8, Crv.Name),
                new JwtProperty(JwkParameterNames.XUtf8, Base64Url.Encode(X)),
                new JwtProperty(JwkParameterNames.YUtf8, Base64Url.Encode(Y))
            };

            return jwtObject;
        }

        internal static ECJwk FromJsonReaderFast(ref Utf8JsonReader reader)
        {
            var key = new ECJwk();
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var propertyName = reader.ValueSpan;
                ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                        switch (propertyName.Length)
                        {
                            case 1 when propertyNameRef == (byte)'x':
                                key._x = Base64Url.Decode(reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'y':
                                key._y = Base64Url.Decode(reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'d':
                                key._d = Base64Url.Decode(reader.ValueSpan);
                                break;

                            case 3 when IntegerMarshal.ReadUInt24(ref propertyNameRef) == crv:
                                key.Crv = EllipticalCurve.FromSpan(reader.ValueSpan);
                                break;
                            case 3:
                                PopulateThree(ref reader, ref propertyNameRef, key);
                                break;

                            case 8:
                                PopulateEight(ref reader, ref propertyNameRef, key);
                                break;
                            default:
                                break;
                        }
                        break;
                    case JsonTokenType.StartObject:
                        PopulateObject(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        PopulateArray(ref reader, ref propertyNameRef, propertyName.Length, key);
                        break;
                    default:
                        break;
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return key;
        }

        internal static ECJwk Populate(JwtObject @object)
        {
            var key = new ECJwk();
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                var name = property.Utf8Name;
                switch (property.Type)
                {
                    case JwtTokenType.String:
                        if (name.SequenceEqual(JwkParameterNames.CrvUtf8))
                        {
                            key.Crv = EllipticalCurve.FromString((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.XUtf8))
                        {
                            key._x = Base64Url.Decode((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.YUtf8))
                        {
                            key._y = Base64Url.Decode((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.DUtf8))
                        {
                            key._d = Base64Url.Decode((string)property.Value!);
                        }
                        else
                        {
                            key.Populate(name, (string)property.Value!);
                        }
                        break;
                    case JwtTokenType.Utf8String:
                        key.Populate(name, (byte[])property.Value!);
                        break;
                    case JwtTokenType.Array:
                        key.Populate(name, (JwtArray)property.Value!);
                        break;
                    default:
                        break;
                }
            }

            return key;
        }

        /// <inheritsdoc />
        public override void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            base.WriteTo(writer);
            writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);

            // X & Y & D have the same length
            Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(_x.Length)];

            WriteBase64UrlProperty(writer, buffer, _x, JwkParameterNames.XUtf8);
            WriteBase64UrlProperty(writer, buffer, _y, JwkParameterNames.YUtf8);

            WriteOptionalBase64UrlProperty(writer, buffer, _d, JwkParameterNames.DUtf8);
            writer.WriteEndObject();
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (!(other is ECJwk key))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return Crv.Id == key.Crv.Id &&
                X.SequenceEqual(key.X) &&
                Y.SequenceEqual(key.Y);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            unchecked
            {
                const int p = 16777619;

                int hash = ((int)2166136261 ^ Crv.Id) * p;

                var x = _x;
                if (x.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref x[0])) * p;
                }
                else
                {
                    for (int i = 0; i < x.Length; i++)
                    {
                        hash = (hash ^ x[i]) * p;
                    }
                }

                var y = _y;
                if (y.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref y[0])) * p;
                }
                else
                {
                    for (int i = 0; i < y.Length; i++)
                    {
                        hash = (hash ^ y[i]) * p;
                    }
                }

                return hash;
            }
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_x != null)
            {
                CryptographicOperations.ZeroMemory(_x);
            }

            if (_y != null)
            {
                CryptographicOperations.ZeroMemory(_y);
            }
        }
    }
}
#endif
