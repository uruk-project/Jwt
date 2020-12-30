// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Cryptography;
using CryptographicOperations = JsonWebToken.Cryptography.CryptographicOperations;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a RSA JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class RsaJwk : AsymmetricJwk
    {
        private const ushort qi = (ushort)26993u;
        private const ushort dp = (ushort)28772u;
        private const ushort dq = (ushort)29028u;

        private RSAParameters _parameters;

#nullable disable
        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(RSAParameters rsaParameters)
        {
            Verify(rsaParameters);
            _parameters = rsaParameters;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(RSAParameters rsaParameters, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Verify(rsaParameters);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }

            _parameters = rsaParameters;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(RSAParameters rsaParameters, SignatureAlgorithm alg)
            : base(alg)
        {
            Verify(rsaParameters);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }

            _parameters = rsaParameters;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(string n, string e, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            Initialize(n: n, e: e);
            if (!SupportSignature(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(string n, string e, KeyManagementAlgorithm algorithm)
            : base(algorithm)
        {
            Initialize(n: n, e: e);
            if (!SupportKeyManagement(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(string n, string e)
        {
            Initialize(n: n, e: e);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(byte[] n, byte[] e, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            Initialize(n, e);
            if (!SupportSignature(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(byte[] n, byte[] e, KeyManagementAlgorithm algorithm)
            : base(algorithm)
        {
            Initialize(n, e);
            if (!SupportKeyManagement(algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(algorithm);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(byte[] n, byte[] e)
        {
            Initialize(n: n, e: e);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk()
        {
        }
#nullable enable

        private void Initialize(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] qi)
        {
            if (dp is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.dp);
            }

            if (dq is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.dq);
            }

            if (q is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.q);
            }

            if (qi is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.qi);
            }

            if (p is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.p);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _parameters.D = d;
            _parameters.DP = dp;
            _parameters.DQ = dq;
            _parameters.InverseQ = qi;
            _parameters.P = p;
            _parameters.Q = q;
            _parameters.Modulus = n;
            _parameters.Exponent = e;

        }

        private void Initialize(string n, string e, string d, string p, string q, string dp, string dq, string qi)
        {
            if (dp is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.dp);
            }

            if (dq is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.dq);
            }

            if (q is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.q);
            }

            if (qi is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.qi);
            }

            if (p is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.p);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _parameters.D = Base64Url.Decode(d);
            _parameters.DP = Base64Url.Decode(dp);
            _parameters.DQ = Base64Url.Decode(dq);
            _parameters.InverseQ = Base64Url.Decode(qi);
            _parameters.P = Base64Url.Decode(p);
            _parameters.Q = Base64Url.Decode(q);
            _parameters.Modulus = Base64Url.Decode(n);
            _parameters.Exponent = Base64Url.Decode(e);
        }

        private static void Verify(RSAParameters rsaParameters)
        {
            if (rsaParameters.Modulus is null) throw new ArgumentNullException(nameof(rsaParameters.Modulus));
            if (rsaParameters.Exponent is null) throw new ArgumentNullException(nameof(rsaParameters.Exponent));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Initialize(string n, string e)
        {
            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            _parameters.Modulus = Base64Url.Decode(n);
            _parameters.Exponent = Base64Url.Decode(e);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Initialize(byte[] n, byte[] e)
        {

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            _parameters.Modulus = n;
            _parameters.Exponent = e;
        }

        /// <inheritdoc/>
        public override bool HasPrivateKey => !(_parameters.D is null);

        /// <inheritsdoc />
        public override JsonEncodedText Kty => JwkTypeNames.Rsa;

        /// <summary>
        /// Exports the RSA parameters from the <see cref="RsaJwk"/>.
        /// </summary>
        /// <returns></returns>
        public RSAParameters ExportParameters()
        {
            return _parameters;
        }

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Rsa;
        }

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Rsa;
        }

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm)
        {
            return false;
        }

        /// <inheritsdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
        {
            return new RsaSigner(this, algorithm);
        }

        /// <inheritsdoc />
        protected override SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm)
        {
            return new RsaSignatureVerifier(this, algorithm);
        }

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            return new RsaKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
        }

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            return new RsaKeyUnwrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
        }

        /// <inheritsdoc />
        public override int KeySizeInBits => _parameters.Modulus!.Length << 3;

        /// <summary>
        /// Gets the 'd' (RSA - Private Exponent).
        /// </summary>
        public ReadOnlySpan<byte> D => _parameters.D;

        /// <summary>
        /// Gets or sets the 'dp' (First Factor CRT Exponent).
        /// </summary>
        public ReadOnlySpan<byte> DP => _parameters.DP;

        /// <summary>
        /// Gets or sets the 'dq' (Second Factor CRT Exponent).
        /// </summary>
        public ReadOnlySpan<byte> DQ => _parameters.DQ;

        /// <summary>
        /// Gets or sets the 'e' ( Exponent).
        /// </summary>
        public ReadOnlySpan<byte> E => _parameters.Exponent;

        /// <summary>
        /// Gets or sets the 'n' (Modulus).
        /// </summary>
        public ReadOnlySpan<byte> N => _parameters.Modulus;

        /// <summary>
        /// Gets or sets the 'p' (First Prime Factor).
        /// </summary>
        public ReadOnlySpan<byte> P => _parameters.P;

        /// <summary>
        /// Gets or sets the 'q' (Second  Prime Factor).
        /// </summary>
        public ReadOnlySpan<byte> Q => _parameters.Q;

        /// <summary>
        /// Gets or sets the 'qi' (First CRT Coefficient).
        /// </summary>
        public ReadOnlySpan<byte> QI => _parameters.InverseQ;

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(algorithm.RequiredKeySizeInBits, algorithm, withPrivateKey: true, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(algorithm.RequiredKeySizeInBits, algorithm, withPrivateKey: true, computeThumbprint);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(algorithm.RequiredKeySizeInBits, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(algorithm.RequiredKeySizeInBits, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits, SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, algorithm, withPrivateKey: true, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, algorithm, withPrivateKey: true, computeThumbprint);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, withPrivateKey: true, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits, SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, algorithm, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits, bool computeThumbprint = true)
            => GenerateKey(sizeInBits, withPrivateKey: false, computeThumbprint: computeThumbprint);

        /// <summary>
        /// Generates a new RSA key.
        /// </summary>
        /// <param name="sizeInBits">The key size in bits.</param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        private static RsaJwk GenerateKey(int sizeInBits, bool withPrivateKey, bool computeThumbprint = true)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
#if NET461 || NET47
            using RSA rsa = new RSACng(sizeInBits);
#else
            using RSA rsa = RSA.Create();
            rsa.KeySize= sizeInBits;
#endif
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, computeThumbprint);
        }

        /// <summary>
        /// Generates a new random <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        private static RsaJwk GenerateKey(int sizeInBits, SignatureAlgorithm algorithm, bool withPrivateKey, bool computeThumbprint = true)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
#if NET461 || NET47
            using RSA rsa = new RSACng(sizeInBits);
#else
            using RSA rsa = RSA.Create();
            rsa.KeySize = sizeInBits;
#endif      
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, algorithm, computeThumbprint);
        }

        /// <summary>
        /// Generates a new random <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        private static RsaJwk GenerateKey(int sizeInBits, KeyManagementAlgorithm algorithm, bool withPrivateKey, bool computeThumbprint = true)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
#if NET461 || NET47
            using RSA rsa = new RSACng(sizeInBits);
#else
            using RSA rsa = RSA.Create();
            rsa.KeySize = sizeInBits;
#endif
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, algorithm, computeThumbprint);
        }

        /// <summary>Converts the current <see cref="RsaJwk"/> key to the public representation. This converted key can be exposed.</summary>
        public override Jwk AsPublicKey()
        {
            var publicParameters = new RSAParameters
            {
                Exponent = _parameters.Exponent,
                Modulus = _parameters.Modulus
            };

            RsaJwk publicKey;
            if (!(KeyManagementAlgorithm is null))
            {
                publicKey = FromParameters(publicParameters, KeyManagementAlgorithm, computeThumbprint: false);
            }
            else if (!(SignatureAlgorithm is null))
            {
                publicKey = FromParameters(publicParameters, SignatureAlgorithm, computeThumbprint: false);
            }
            else
            {
                publicKey = FromParameters(publicParameters, computeThumbprint: false);
            }

            publicKey.Kid = Kid;
            return publicKey;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            SignatureAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi, alg: alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            SignatureAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            SignatureAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, algorithm: alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            SignatureAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            KeyManagementAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            KeyManagementAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromByteArray(
            byte[] n,
            byte[] e,
            KeyManagementAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, algorithm: alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public static RsaJwk FromBase64Url(
            string n,
            string e,
            KeyManagementAlgorithm alg,
            bool computeThumbprint = true)
        {
            var key = new RsaJwk(n: n, e: e, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="alg">The <see cref="KeyManagementAlgorithm"/></param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, KeyManagementAlgorithm alg, bool computeThumbprint = true)
        {
            var key = new RsaJwk(parameters, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/></param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, SignatureAlgorithm alg, bool computeThumbprint)
        {
            var key = new RsaJwk(parameters, alg);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, bool computeThumbprint = true)
        {
            var key = new RsaJwk(parameters);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>Returns a new instance of <see cref="RsaJwk"/>.</summary>
        /// <param name="pem">A PEM-encoded key in PKCS1 (BEGIN RSA PUBLIC/PRIVATE KEY) or PKCS8 (BEGIN PUBLIC/PRIVATE KEY) format.</param>
        /// <remarks>Support unencrypted PKCS#1 public RSA key, unencrypted PKCS#1 private RSA key,
        /// unencrypted PKCS#8 public RSA key, unencrypted PKCS#8 private RSA key. 
        /// Password-protected key is not supported.</remarks>
        public new static RsaJwk FromPem(string pem)
        {
            AsymmetricJwk jwk = PemParser.Read(pem);
            if (!(jwk is RsaJwk rsaJwk))
            {
                jwk.Dispose();
                ThrowHelper.ThrowInvalidOperationException_UnexpectedKeyType(jwk, JwkTypeNames.Rsa.ToString());
                return null;
            }

            return rsaJwk;
        }

        private static ReadOnlySpan<byte> StartCanonicalizeValue => new byte[] { (byte)'{', (byte)'"', (byte)'e', (byte)'"', (byte)':', (byte)'"' };
        private static ReadOnlySpan<byte> MiddleCanonicalizeValue => new byte[] { (byte)'"', (byte)',', (byte)'"', (byte)'k', (byte)'t', (byte)'y', (byte)'"', (byte)':', (byte)'"', (byte)'R', (byte)'S', (byte)'A', (byte)'"', (byte)',', (byte)'"', (byte)'n', (byte)'"', (byte)':', (byte)'"' };
        private static ReadOnlySpan<byte> EndCanonicalizeValue => new byte[] { (byte)'"', (byte)'}' };

        /// <inheritdoc />
        protected internal override void Canonicalize(Span<byte> buffer)
        {
            // {"e":"XXXX","kty":"RSA","n":"XXXX"}
            int offset = StartCanonicalizeValue.Length;
            StartCanonicalizeValue.CopyTo(buffer);
            offset += Base64Url.Encode(E, buffer.Slice(offset));
            MiddleCanonicalizeValue.CopyTo(buffer.Slice(offset));
            offset += MiddleCanonicalizeValue.Length;
            offset += Base64Url.Encode(N, buffer.Slice(offset));
            EndCanonicalizeValue.CopyTo(buffer.Slice(offset));
        }

        /// <inheritdoc />
        protected internal override int GetCanonicalizeSize()
        {
            Debug.Assert(27 == StartCanonicalizeValue.Length + MiddleCanonicalizeValue.Length + EndCanonicalizeValue.Length);
            return 27
                + Base64Url.GetArraySizeRequiredToEncode(_parameters.Exponent!.Length)
                + Base64Url.GetArraySizeRequiredToEncode(_parameters.Modulus!.Length);
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            throw new NotImplementedException();
        }

        internal static Jwk FromJsonReaderFast(ref Utf8JsonReader reader)
        {
            var key = new RsaJwk();

            while (reader.Read())
            {
                if (!(reader.TokenType is JsonTokenType.PropertyName))
                {
                    break;
                }

                ReadOnlySpan<byte> propertyName = reader.ValueSpan;
                ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                        switch (propertyName.Length)
                        {
                            case 1:
                                PopulatOne(ref reader, ref propertyNameRef, key);
                                break;
                            case 2:
                                PopulateTwo(ref reader, ref propertyNameRef, key);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void PopulateTwo(ref Utf8JsonReader reader, ref byte propertyNameRef, RsaJwk key)
        {
            var pKtyShort = IntegerMarshal.ReadUInt16(ref propertyNameRef);
            switch (pKtyShort)
            {
                case qi:
                    key._parameters.InverseQ = Base64Url.Decode(reader.ValueSpan);
                    break;
                case dp:
                    key._parameters.DP = Base64Url.Decode(reader.ValueSpan);
                    break;
                case dq:
                    key._parameters.DQ = Base64Url.Decode(reader.ValueSpan);
                    break;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void PopulatOne(ref Utf8JsonReader reader, ref byte propertyNameRef, RsaJwk key)
        {
            switch (propertyNameRef)
            {
                case (byte)'e':
                    key._parameters.Exponent = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'n':
                    key._parameters.Modulus = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'p':
                    key._parameters.P = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'q':
                    key._parameters.Q = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'d':
                    key._parameters.D = Base64Url.Decode(reader.ValueSpan);
                    break;
            }
        }

        /// <inheritsdoc />
        public override void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            base.WriteTo(writer);

            // the modulus N is always the biggest field
            int requiredBufferSize = Base64Url.GetArraySizeRequiredToEncode(_parameters.Modulus!.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = requiredBufferSize > Constants.MaxStackallocBytes
                                    ? stackalloc byte[requiredBufferSize]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(requiredBufferSize));

                WriteBase64UrlProperty(writer, buffer, _parameters.Exponent!, JwkParameterNames.E);
                WriteBase64UrlProperty(writer, buffer, _parameters.Modulus!, JwkParameterNames.N);

                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.D, JwkParameterNames.D);
                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.DP, JwkParameterNames.DP);
                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.DQ, JwkParameterNames.DQ);
                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.P, JwkParameterNames.P);
                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.Q, JwkParameterNames.Q);
                WriteOptionalBase64UrlProperty(writer, buffer, _parameters.InverseQ, JwkParameterNames.QI);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }

            writer.WriteEndObject();
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_parameters.DP != null)
            {
                CryptographicOperations.ZeroMemory(_parameters.DP);
                CryptographicOperations.ZeroMemory(_parameters.DQ);
                CryptographicOperations.ZeroMemory(_parameters.InverseQ);
                CryptographicOperations.ZeroMemory(_parameters.P);
                CryptographicOperations.ZeroMemory(_parameters.Q);
            }
        }
    }
}
