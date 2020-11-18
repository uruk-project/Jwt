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
        private ECParameters _parameters;

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
        {
            Initialize(crv, d, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y)
        {
            Initialize(crv, d, x, y);
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
            : base(alg)
        {
            Initialize(crv, d, x, y, alg);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, d, x, y, alg);
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
            : base(alg)
        {
            Initialize(crv, d, x, y);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk(in EllipticalCurve crv, string d, string x, string y, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, d, x, y);
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

            _parameters = parameters;
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
        private void Initialize(in EllipticalCurve crv, string d, string x, string y, SignatureAlgorithm alg)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _parameters.D = Base64Url.Decode(d);
            Initialize(crv, x, y, alg);
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
            _parameters.Curve = crv.CurveParameters;
            _parameters.Q.X = Base64Url.Decode(x);
            _parameters.Q.Y = Base64Url.Decode(y);
        }

        private void Initialize(in EllipticalCurve crv, string d, string x, string y)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _parameters.D = Base64Url.Decode(d);
            Initialize(crv, x, y);
        }

        private void Initialize(in EllipticalCurve crv, byte[] x, byte[] y, SignatureAlgorithm alg)
        {
            if (crv.SupportedSignatureAlgorithm != alg)
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, crv);
            }

            Initialize(crv, x, y);
        }

        private void Initialize(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y, SignatureAlgorithm alg)
        {
            _parameters.D = d;
            Initialize(crv, x, y, alg);
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
            _parameters.Curve = crv.CurveParameters;
            _parameters.Q.X = x;
            _parameters.Q.Y = y;
        }

        private void Initialize(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _parameters.D = d;
            Initialize(crv, x, y);
        }

        /// <inheritdoc/>
        public override bool HasPrivateKey => !(_parameters.D is null);

        /// <inheritsdoc />
        public override JsonEncodedText Kty => JwkTypeNames.EllipticCurve;

        /// <summary>
        /// Gets the 'd' (Private Key).
        /// </summary>
        public ReadOnlySpan<byte> D => _parameters.D;

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        public EllipticalCurve Crv { get; private set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        public ReadOnlySpan<byte> X => _parameters.Q.X;

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        public ReadOnlySpan<byte> Y => _parameters.Q.Y;

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
        protected override SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm)
        {
#if SUPPORT_ELLIPTIC_CURVE_SIGNATURE
            return new EcdsaSignatureVerifier(this, algorithm);
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
        public ECParameters ExportParameters(bool includePrivateParameters = false)
        {
            var parameters = new ECParameters
            {
                Q = _parameters.Q,
                Curve = _parameters.Curve
            };
            if (includePrivateParameters)
            {
                parameters.D = _parameters.D;
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
            => GenerateKey(curve, withPrivateKey: true, computeThumbprint: computeThumbprint);
        
        /// <summary>
        /// Generates a private <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePrivateKey(in EllipticalCurve curve, SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(curve, algorithm, withPrivateKey: true, computeThumbprint: computeThumbprint);
        
        /// <summary>
        /// Generates a private <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePrivateKey(in EllipticalCurve curve, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(curve, algorithm, withPrivateKey: true, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a public <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePublicKey(in EllipticalCurve curve, bool computeThumbprint = true)
            => GenerateKey(curve, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a public <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePublicKey(in EllipticalCurve curve, SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(curve, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a public <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GeneratePublicKey(in EllipticalCurve curve, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(curve, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

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
        /// <param name="algorithm"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, SignatureAlgorithm algorithm, bool withPrivateKey, bool computeThumbprint = true)
        {
            ECParameters parameters = GenerateParameters(curve, withPrivateKey);
            return FromParameters(parameters, algorithm, computeThumbprint: computeThumbprint);
        }

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="algorithm"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, KeyManagementAlgorithm algorithm, bool withPrivateKey, bool computeThumbprint = true)
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

        private static ReadOnlySpan<byte> StartCanonicalizeValue => new byte[] { (byte)'{', (byte)'"', (byte)'c', (byte)'r', (byte)'v', (byte)'"', (byte)':', (byte)'"' };
        private static ReadOnlySpan<byte> Middle1CanonicalizeValue => new byte[] { (byte)'"', (byte)',', (byte)'"', (byte)'k', (byte)'t', (byte)'y', (byte)'"', (byte)':', (byte)'"', (byte)'E', (byte)'C', (byte)'"', (byte)',', (byte)'"', (byte)'x', (byte)'"', (byte)':', (byte)'"' };
        private static ReadOnlySpan<byte> Middle2CanonicalizeValue => new byte[] { (byte)'"', (byte)',', (byte)'"', (byte)'y' ,(byte)'"', (byte)':', (byte)'"' };
        private static ReadOnlySpan<byte> EndCanonicalizeValue => new byte[] { (byte)'"', (byte)'}' };

        /// <inheritdoc />
        protected override void Canonicalize(Span<byte> buffer)
        {
            // {"crv":"XXXX","kty":"EC","x":"XXXX","y":"XXXX"}
            int offset = StartCanonicalizeValue.Length;
            StartCanonicalizeValue.CopyTo(buffer);
            Crv.Name.AsSpan().CopyTo(buffer.Slice(offset));
            offset += Crv.Name.Length;
            Middle1CanonicalizeValue.CopyTo(buffer.Slice(offset));
            offset += Middle1CanonicalizeValue.Length;
            offset += Base64Url.Encode(X, buffer.Slice(offset));
            Middle2CanonicalizeValue.CopyTo(buffer.Slice(offset));
            offset += Middle2CanonicalizeValue.Length;
            offset += Base64Url.Encode(Y, buffer.Slice(offset));
            EndCanonicalizeValue.CopyTo(buffer.Slice(offset));
        }

        /// <inheritdoc />
        protected override int GetCanonicalizeSize()
        {
            Debug.Assert(35 == 
                StartCanonicalizeValue.Length 
                + Middle1CanonicalizeValue.Length 
                + Middle2CanonicalizeValue.Length
                + EndCanonicalizeValue.Length); 
            return 35
                + Base64Url.GetArraySizeRequiredToEncode(Crv.Name.Length) 
                + Base64Url.GetArraySizeRequiredToEncode(X!.Length)
                + Base64Url.GetArraySizeRequiredToEncode(Y!.Length);
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
                ThrowHelper.ThrowInvalidOperationException_UnexpectedKeyType(jwk, JwkTypeNames.EllipticCurve.ToString());
                return null;
            }

            return ecJwk;
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
                                key._parameters.Q.X = Base64Url.Decode(reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'y':
                                key._parameters.Q.Y = Base64Url.Decode(reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'d':
                                key._parameters.D = Base64Url.Decode(reader.ValueSpan);
                                break;

                            case 3 when IntegerMarshal.ReadUInt24(ref propertyNameRef) == crv:
                                key.Crv = EllipticalCurve.FromSpan(reader.ValueSpan);
                                key._parameters.Curve = key.Crv.CurveParameters;
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

        /// <inheritsdoc />
        public override void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            base.WriteTo(writer);
            writer.WriteString(JwkParameterNames.Crv, Crv.Name);

            // X & Y & D have the same length
            Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(_parameters.Q.X!.Length)];

            WriteBase64UrlProperty(writer, buffer, _parameters.Q.X!, JwkParameterNames.X);
            WriteBase64UrlProperty(writer, buffer, _parameters.Q.Y!, JwkParameterNames.Y);

            WriteOptionalBase64UrlProperty(writer, buffer, _parameters.D, JwkParameterNames.D);
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

                var x = _parameters.Q.X!;
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

                var y = _parameters.Q.Y!;
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
            CryptographicOperations.ZeroMemory(_parameters.Q.X);
            CryptographicOperations.ZeroMemory(_parameters.Q.Y);
        }
    }
}
#endif
