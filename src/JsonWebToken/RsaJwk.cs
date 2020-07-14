// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Cryptography;
using JsonWebToken.Internal;

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

        private byte[] _e;
        private byte[] _n;
        private byte[]? _dp;
        private byte[]? _dq;
        private byte[]? _p;
        private byte[]? _q;
        private byte[]? _qi;

#nullable disable
        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi)
            : base(d)
        {
            Initialize(n, e, p, q, dp, dq, qi);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            string e,
            string n)
            : base(d)
        {
            Initialize(p, q, dp, dq, qi, e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(RSAParameters rsaParameters)
        {
            Initialize(rsaParameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(byte[] e, byte[] n)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(string e, string n)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(n, e, p, q, dp, dq, qi);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            string e,
            string n,
            SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(p, q, dp, dq, qi, e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(RSAParameters rsaParameters, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(rsaParameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(byte[] e, byte[] n, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(string e, string n, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            byte[] n,
            byte[] e,
            byte[] d,
            byte[] p,
            byte[] q,
            byte[] dp,
            byte[] dq,
            byte[] qi,
            KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(n, e, p, q, dp, dq, qi);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(
            string d,
            string p,
            string q,
            string dp,
            string dq,
            string qi,
            string e,
            string n,
            KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(p, q, dp, dq, qi, e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(RSAParameters rsaParameters, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(rsaParameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(byte[] e, byte[] n, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        public RsaJwk(string e, string n, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(e, n);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        private RsaJwk()
        {
        }
#nullable enable

        private void Initialize(byte[] n, byte[] e, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] qi)
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

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            _dp = dp;
            _dq = dq;
            _qi = qi;
            _p = p;
            _q = q;
            _e = e;
            _n = n;
        }

        private void Initialize(string p, string q, string dp, string dq, string qi, string e, string n)
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

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            _dp = Base64Url.Decode(dp);
            _dq = Base64Url.Decode(dq);
            _qi = Base64Url.Decode(qi);
            _p = Base64Url.Decode(p);
            _q = Base64Url.Decode(q);
            _e = Base64Url.Decode(e);
            _n = Base64Url.Decode(n);
        }

        private void Initialize(RSAParameters rsaParameters)
        {
            _d = rsaParameters.D;
            _dp = rsaParameters.DP;
            _dq = rsaParameters.DQ;
            _qi = rsaParameters.InverseQ;
            _p = rsaParameters.P;
            _q = rsaParameters.Q;
            _e = rsaParameters.Exponent;
            _n = rsaParameters.Modulus;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Initialize(string e, string n)
        {
            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            _e = Base64Url.Decode(e);
            _n = Base64Url.Decode(n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Initialize(byte[] e, byte[] n)
        {

            if (e is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.e);
            }

            if (n is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.n);
            }

            _e = e;
            _n = n;
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.Rsa;

        /// <summary>
        /// Exports the RSA parameters from the <see cref="RsaJwk"/>.
        /// </summary>
        /// <returns></returns>
        public RSAParameters ExportParameters()
        {
            RSAParameters parameters = new RSAParameters
            {
                D = _d,
                DP = _dp,
                DQ = _dq,
                InverseQ = _qi,
                P = _p,
                Q = _q,
                Exponent = _e,
                Modulus = _n
            };

            return parameters;
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
        public override int KeySizeInBits => _n.Length << 3;

        /// <summary>
        /// Gets or sets the 'dp' (First Factor CRT Exponent).
        /// </summary>
        public ReadOnlySpan<byte> DP => _dp;

        /// <summary>
        /// Gets or sets the 'dq' (Second Factor CRT Exponent).
        /// </summary>
        public ReadOnlySpan<byte> DQ => _dq;

        /// <summary>
        /// Gets or sets the 'e' ( Exponent).
        /// </summary>
        public ReadOnlySpan<byte> E => _e;

        /// <summary>
        /// Gets or sets the 'n' (Modulus).
        /// </summary>
        public ReadOnlySpan<byte> N => _n;

        /// <summary>
        /// Gets or sets the 'p' (First Prime Factor).
        /// </summary>
        public ReadOnlySpan<byte> P => _p;

        /// <summary>
        /// Gets or sets the 'q' (Second  Prime Factor).
        /// </summary>
        public ReadOnlySpan<byte> Q => _q;

        /// <summary>
        /// Gets or sets the 'qi' (First CRT Coefficient).
        /// </summary>
        public ReadOnlySpan<byte> QI => _qi;

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits, SignatureAlgorithm algorithm) 
            => GenerateKey(sizeInBits, withPrivateKey: true, algorithm);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits, KeyManagementAlgorithm algorithm)
            => GenerateKey(sizeInBits, withPrivateKey: true, algorithm);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePrivateKey(int sizeInBits)
            => GenerateKey(sizeInBits, true);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits, SignatureAlgorithm algorithm) 
            => GenerateKey(sizeInBits, withPrivateKey: false, algorithm);

        /// <summary>
        /// Generates a new random public <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits, KeyManagementAlgorithm algorithm) 
            => GenerateKey(sizeInBits, withPrivateKey: false, algorithm);

        /// <summary>
        /// Generates a new random private <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static RsaJwk GeneratePublicKey(int sizeInBits) 
            => GenerateKey(sizeInBits, false);

        /// <summary>
        /// Generates a new RSA key.
        /// </summary>
        /// <param name="sizeInBits">The key size in bits.</param>
        /// <param name="withPrivateKey"></param>
        /// <returns></returns>
        public static RsaJwk GenerateKey(int sizeInBits, bool withPrivateKey)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
            using RSA rsa = new RSACng(sizeInBits);
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, false);
        }

        /// <summary>
        /// Generates a new random <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GenerateKey(int sizeInBits, bool withPrivateKey, SignatureAlgorithm algorithm)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
            using RSA rsa = new RSACng(sizeInBits);
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, algorithm, false);
        }

        /// <summary>
        /// Generates a new random <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static RsaJwk GenerateKey(int sizeInBits, bool withPrivateKey, KeyManagementAlgorithm algorithm)
        {
#if SUPPORT_SPAN_CRYPTO
            using RSA rsa = RSA.Create(sizeInBits);
#else
            using RSA rsa = new RSACng(sizeInBits);
#endif
            RSAParameters rsaParameters = rsa.ExportParameters(withPrivateKey);

            return FromParameters(rsaParameters, algorithm, false);
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/></param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, KeyManagementAlgorithm algorithm, bool computeThumbprint)
        {
            var key = new RsaJwk(parameters, algorithm);
            if (computeThumbprint)
            {
                FillThumbprint(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/></param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, SignatureAlgorithm algorithm, bool computeThumbprint)
        {
            var key = new RsaJwk(parameters, algorithm);
            if (computeThumbprint)
            {
                FillThumbprint(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        /// <param name="computeThumbprint">Defines whether the thumbprint of the key should be computed </param>
        public static RsaJwk FromParameters(RSAParameters parameters, bool computeThumbprint)
        {
            var key = new RsaJwk(parameters);
            if (computeThumbprint)
            {
                FillThumbprint(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that contains the key parameters.</param>
        public static RsaJwk FromParameters(RSAParameters parameters)
            => FromParameters(parameters, false);

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="pem">A PEM-encoded key in PKCS1 (BEGIN RSA PUBLIC/PRIVATE KEY) or PKCS8 (BEGIN PUBLIC/PRIVATE KEY) format.</param>
        /// Support unencrypted PKCS#1 public RSA key, unencrypted PKCS#1 private RSA key,
        /// unencrypted PKCS#8 public RSA key, unencrypted PKCS#8 private RSA key. 
        /// Password-protected key is not supported.
        public new static RsaJwk FromPem(string pem)
        {
            AsymmetricJwk jwk = PemParser.Read(pem);
            if (!(jwk is RsaJwk rsaJwk))
            {
                jwk.Dispose();
                ThrowHelper.ThrowInvalidOperationException_UnexpectedKeyType(jwk, Utf8.GetString(JwkTypeNames.Rsa));
                return null;
            }

            return rsaJwk;
        }

        /// <inheritdoc />
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            writer.WriteStartObject();

            // the RSA exponent E is always smaller than the modulus N
            int requiredBufferSize = Base64Url.GetArraySizeRequiredToEncode(_n.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = requiredBufferSize > Constants.MaxStackallocBytes
                                    ? stackalloc byte[requiredBufferSize]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(requiredBufferSize));
                int bytesWritten = Base64Url.Encode(E, buffer);
                writer.WriteString(JwkParameterNames.EUtf8, buffer.Slice(0, bytesWritten));
                writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
                bytesWritten = Base64Url.Encode(N, buffer);
                writer.WriteString(JwkParameterNames.NUtf8, buffer.Slice(0, bytesWritten));
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
            writer.WriteEndObject();
            writer.Flush();
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            throw new NotImplementedException();
        }

        internal static RsaJwk Populate(JwtObject @object)
        {
            var key = new RsaJwk();
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                if (!(property.Value is null))
                {
                    var name = property.Utf8Name;
                    switch (property.Type)
                    {
                        case JwtTokenType.String:
                            PopulateStringProperty(key, property, name);
                            break;
                        case JwtTokenType.Utf8String:
                            key.Populate(name, (byte[])property.Value);
                            break;
                        case JwtTokenType.Array:
                            key.Populate(name, (JwtArray)property.Value);
                            break;
                        default:
                            break;
                    }
                }
            }

            return key;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void PopulateStringProperty(RsaJwk key, JwtProperty property, ReadOnlySpan<byte> name)
        {
            string value = (string)property.Value!;
            if (name.SequenceEqual(JwkParameterNames.NUtf8))
            {
                key._n = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.EUtf8))
            {
                key._e = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.DUtf8))
            {
                key._d = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.DPUtf8))
            {
                key._dp = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.DQUtf8))
            {
                key._dq = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.PUtf8))
            {
                key._p = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.QUtf8))
            {
                key._q = Base64Url.Decode(value);
            }
            else if (name.SequenceEqual(JwkParameterNames.QIUtf8))
            {
                key._qi = Base64Url.Decode(value);
            }
            else
            {
                key.Populate(name, value);
            }
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
                    key._qi = Base64Url.Decode(reader.ValueSpan);
                    break;
                case dp:
                    key._dp = Base64Url.Decode(reader.ValueSpan);
                    break;
                case dq:
                    key._dq = Base64Url.Decode(reader.ValueSpan);
                    break;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void PopulatOne(ref Utf8JsonReader reader, ref byte propertyNameRef, RsaJwk key)
        {
            switch (propertyNameRef)
            {
                case (byte)'e':
                    key._e = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'n':
                    key._n = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'p':
                    key._p = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'q':
                    key._q = Base64Url.Decode(reader.ValueSpan);
                    break;
                case (byte)'d':
                    key._d = Base64Url.Decode(reader.ValueSpan);
                    break;
            }
        }

        /// <inheritsdoc />
        public override void WriteTo(Utf8JsonWriter writer)
        {
            base.WriteTo(writer);

            // the modulus N is always the biggest field
            int requiredBufferSize = Base64Url.GetArraySizeRequiredToEncode(_n.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = requiredBufferSize > Constants.MaxStackallocBytes
                                    ? stackalloc byte[requiredBufferSize]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(requiredBufferSize));

                WriteBase64UrlProperty(writer, buffer, _e, JwkParameterNames.EUtf8);
                WriteBase64UrlProperty(writer, buffer, _n, JwkParameterNames.NUtf8);

                WriteOptionalBase64UrlProperty(writer, buffer, _d, JwkParameterNames.DUtf8);
                WriteOptionalBase64UrlProperty(writer, buffer, _dp, JwkParameterNames.DPUtf8);
                WriteOptionalBase64UrlProperty(writer, buffer, _dq, JwkParameterNames.DQUtf8);
                WriteOptionalBase64UrlProperty(writer, buffer, _p, JwkParameterNames.PUtf8);
                WriteOptionalBase64UrlProperty(writer, buffer, _q, JwkParameterNames.QUtf8);
                WriteOptionalBase64UrlProperty(writer, buffer, _qi, JwkParameterNames.QIUtf8);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (!(other is RsaJwk key))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return
                E.SequenceEqual(key.E) &&
                N.SequenceEqual(key.N);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            unchecked
            {
                const int p = 16777619;

                int hash = (int)2166136261;

                var e = _e;
                if (e.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref e[0])) * p;
                }
                else
                {
                    for (int i = 0; i < e.Length; i++)
                    {
                        hash = (hash ^ e[i]) * p;
                    }
                }

                var n = _n;
                if (n.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref n[0])) * p;
                }
                else
                {
                    for (int i = 0; i < n.Length; i++)
                    {
                        hash = (hash ^ n[i]) * p;
                    }
                }

                return hash;
            }
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_dp != null)
            {
                CryptographicOperations.ZeroMemory(_dp);
            }

            if (_dq != null)
            {
                CryptographicOperations.ZeroMemory(_dq);
            }

            if (_qi != null)
            {
                CryptographicOperations.ZeroMemory(_qi);
            }

            if (_p != null)
            {
                CryptographicOperations.ZeroMemory(_p);
            }

            if (_q != null)
            {
                CryptographicOperations.ZeroMemory(_q);
            }
        }
    }
}
