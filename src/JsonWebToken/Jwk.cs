// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class Jwk : IEquatable<Jwk>, IDisposable
    {
        /// <summary>
        /// An empty <see cref="Jwk"/>.
        /// </summary>
        public static Jwk Empty = new NullJwk();

        private CryptographicStore<Signer> _signers;
        private CryptographicStore<KeyWrapper> _keyWrappers;
        private CryptographicStore<AuthenticatedEncryptor> _encryptors;

        private bool? _isSigningKey;
        private SignatureAlgorithm _signatureAlgorithm;
        private bool? _isEncryptionKey;
        private KeyManagementAlgorithm _keyManagementAlgorithm;
        private byte[] _use;
        private IList<string> _keyOps;
        private List<byte[]> _x5c;

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        public Jwk()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        public Jwk(SignatureAlgorithm alg)
        {
            Alg = alg.Utf8Name;
            _signatureAlgorithm = alg;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        public Jwk(KeyManagementAlgorithm alg)
        {
            Alg = alg.Utf8Name;
            _keyManagementAlgorithm = alg;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        public Jwk(byte[] alg)
        {
            Alg = alg;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        public Jwk(string alg)
        {
            Alg = Encoding.UTF8.GetBytes(alg);
        }

        /// <summary>
        /// Gets or sets the 'alg' (KeyType).
        /// </summary>
        public byte[] Alg { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations).
        /// </summary>
        public IList<string> KeyOps
        {
            get
            {
                if (_keyOps == null)
                {
                    _keyOps = new List<string>();
                }

                return _keyOps;
            }
        }
        /// <summary>
        /// Gets or sets the 'kid' (Key ID).
        /// </summary>
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        public abstract ReadOnlySpan<byte> Kty { get; }

        // TODO : Replace string by another type faster to compare (4 comparisons).
        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>
        public byte[] Use
        {
            get => _use;
            set
            {
                _use = value;
                _isSigningKey = value == null || JwkUseNames.Sig.SequenceEqual(value);
                _isEncryptionKey = value == null || JwkUseNames.Enc.SequenceEqual(value);
            }
        }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain).
        /// </summary>
        public List<byte[]> X5c
        {
            get
            {
                if (_x5c == null)
                {
                    _x5c = new List<byte[]>();
                }

                return _x5c;
            }
        }

        /// <summary>
        /// Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint).
        /// </summary>
        public byte[] X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-256 thumbprint).
        /// </summary>
        public byte[] X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL).
        /// </summary>
        public string X5u { get; set; }

        /// <summary>
        /// Gets the key size of <see cref="Jwk"/>.
        /// </summary>
        public abstract int KeySizeInBits { get; }

        /// <summary>
        /// Gets the X.509 certificate chain.
        /// </summary>
        public IList<Jwk> X509CertificateChain
        {
            get
            {
                if (_x5c == null)
                {
                    return null;
                }

                var certificateChain = new List<Jwk>(_x5c.Count);
                foreach (var certString in _x5c)
                {
                    using (var certificate = new X509Certificate2(certString))
                    {
                        var key = FromX509Certificate(certificate, false);
                        key.Kid = Kid;
                        certificateChain.Add(key);
                    }
                }

                return certificateChain;
            }
        }

        internal bool IsSigningKey
        {
            get
            {
                if (!_isSigningKey.HasValue)
                {
                    var use = Use;
                    _isSigningKey = use == null || JwkUseNames.Sig.SequenceEqual(use);
                }

                return _isSigningKey.Value;
            }
        }

        internal SignatureAlgorithm SignatureAlgorithm
        {
            get
            {
                if (_signatureAlgorithm == null)
                {
                    var alg = Alg;
                    if (alg != null)
                    {
                        SignatureAlgorithm.TryParse(alg, out _signatureAlgorithm);
                    }
                }

                return _signatureAlgorithm;
            }
        }

        internal bool IsEncryptionKey
        {
            get
            {
                if (!_isEncryptionKey.HasValue)
                {
                    var use = Use;
                    _isEncryptionKey = use == null || JwkUseNames.Enc.SequenceEqual(use);
                }

                return _isEncryptionKey.Value;
            }
        }

        internal KeyManagementAlgorithm KeyManagementAlgorithm
        {
            get
            {
                if (_keyManagementAlgorithm == null)
                {
                    var alg = Alg;
                    if (alg != null)
                    {
                        KeyManagementAlgorithm.TryParse(alg, out _keyManagementAlgorithm);
                    }
                }

                return _keyManagementAlgorithm;
            }
        }

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(SignatureAlgorithm algorithm);

        internal unsafe static Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            bool fastPath = true;
            JwtObject jwk = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return FromJwtObject(jwk);

                    case JsonTokenType.PropertyName:
                        var nameSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        if (fastPath && nameSpan.SequenceEqual(JwkParameterNames.KtyUtf8))
                        {
                            reader.Read();
                            var valueSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                            fixed (byte* pKty = valueSpan)
                            {
                                var pKtyShort = (short*)pKty;
                                switch (valueSpan.Length)
                                {
                                    case 2:
                                        /* EC */
                                        if (*pKtyShort == 17221u)
                                        {
                                            return ECJwk.FromJsonReaderFast(ref reader);
                                        }

                                        ThrowHelper.ThrowNotSupportedException_Jwk(valueSpan);
                                        break;
                                    case 3:
                                        switch (*pKtyShort)
                                        {
                                            /* RSA */
                                            case 21330 when *(pKty + 2) == (byte)'A':
                                                return RsaJwk.FromJsonReaderFast(ref reader);
                                            /* oct */
                                            case 25455 when *(pKty + 2) == (byte)'t':
                                                return SymmetricJwk.FromJsonReaderFast(ref reader);
                                            default:
                                                ThrowHelper.ThrowNotSupportedException_Jwk(valueSpan);
                                                break;
                                        }
                                        break;
                                    default:
                                        ThrowHelper.ThrowNotSupportedException_Jwk(valueSpan);
                                        break;
                                }
                            }
                        }

                        if (fastPath)
                        {
                            fastPath = false;
                            jwk = new JwtObject();
                        }

                        var name = nameSpan;
                        reader.Read();
                        var type = reader.TokenType;
                        switch (type)
                        {
                            case JsonTokenType.String:
                                fixed (byte* pName = name)
                                {
                                    if (name.Length == 3)
                                    {
                                        ushort* pNameShort = (ushort*)(pName + 1);
                                        switch (name[0])
                                        {
                                            /* alg */
                                            case (byte)'a' when *pNameShort == 26476u:
                                                jwk.Add(new JwtProperty(WellKnownProperty.Alg, reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()));
                                                break;
                                            /* use */
                                            case (byte)'u' when *pNameShort == 25971u:
                                                jwk.Add(new JwtProperty(name, reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()));
                                                continue;
                                            /* x5t */
                                            case (byte)'x' when *pNameShort == 29749u:
                                                jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray())));
                                                continue;
                                            /* kid */
                                            case (byte)'k' when *pNameShort == 25705u:
                                                jwk.Add(new JwtProperty(WellKnownProperty.Kid, reader.GetString()));
                                                continue;
                                        }
                                    }
                                    else if (name.Length == 8 && name.SequenceEqual(JwkParameterNames.X5tS256Utf8))
                                    {
                                        jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray())));
                                        continue;
                                    }
                                }
                                jwk.Add(new JwtProperty(name, reader.GetString()));
                                break;
                            case JsonTokenType.StartObject:
                                var jwtObject = JsonParser.ReadJsonObject(ref reader);
                                jwk.Add(new JwtProperty(name, jwtObject));
                                break;
                            case JsonTokenType.True:
                                jwk.Add(new JwtProperty(name, true));
                                break;
                            case JsonTokenType.False:
                                jwk.Add(new JwtProperty(name, false));
                                break;
                            case JsonTokenType.Null:
                                jwk.Add(new JwtProperty(name));
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64(out long longValue))
                                {
                                    jwk.Add(new JwtProperty(name, longValue));
                                }
                                else
                                {
                                    if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        jwk.Add(new JwtProperty(name, doubleValue));
                                    }
                                    else
                                    {
                                        ThrowHelper.ThrowFormatException_NotSUpportedNumberValue(name);
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                fixed (byte* pName = name)
                                {
                                    // x5c
                                    if (name.Length == 3 && *pName == (byte)'x' && *(ushort*)(pName + 1) == 25397u)
                                    {
                                        jwk.Add(new JwtProperty(name, ReadBase64StringJsonArray(ref reader)));
                                        break;
                                    }
                                }

                                var array = JsonParser.ReadJsonArray(ref reader);
                                jwk.Add(new JwtProperty(name, array));
                                break;
                            default:
                                ThrowHelper.ThrowFormatException_MalformedJson();
                                break;
                        }
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }

            ThrowHelper.ThrowArgumentException_MalformedKey();
            return null;
        }

        private static unsafe JwtArray ReadBase64StringJsonArray(ref Utf8JsonReader reader)
        {
            var array = new JwtArray(new List<JwtValue>(2));
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndArray:
                        return array;
                    case JsonTokenType.String:
                        var value = reader.GetString();
                        array.Add(new JwtValue(Convert.FromBase64String(value)));
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }

            ThrowHelper.ThrowFormatException_MalformedJson();
            return array;
        }

        private static Jwk FromJwtObject(JwtObject jwk)
        {
            if (jwk.TryGetValue(JwkParameterNames.KtyUtf8, out var property))
            {
                ReadOnlySpan<byte> kty = Encoding.UTF8.GetBytes((string)property.Value);
                if (kty.SequenceEqual(JwkTypeNames.Octet))
                {
                    return SymmetricJwk.Populate(jwk);
                }
                else if (kty.SequenceEqual(JwkTypeNames.EllipticCurve))
                {
                    return ECJwk.Populate(jwk);
                }
                else if (kty.SequenceEqual(JwkTypeNames.Rsa))
                {
                    return RsaJwk.Populate(jwk);
                }
            }

            ThrowHelper.ThrowArgumentException_MalformedKey();
            return null;
        }

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="EncryptionAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(EncryptionAlgorithm algorithm);

        /// <summary>
        /// Returns a string that represents the <see cref="Jwk"/> in JSON.
        /// </summary>
        public override string ToString()
        {
            using (var bufferWriter = new ArrayBufferWriter())
            {
                using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
                {
                    writer.WriteStartObject();
                    WriteTo(writer);
                    writer.WriteEndObject();
                }

                var input = bufferWriter.WrittenSpan;
#if NETSTANDARD2_0
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }

        /// <summary>
        /// Serializes the <see cref="Jwk"/> into its JSON representation.
        /// </summary>
        /// <param name="bufferWriter"></param>
        public void Serialize(IBufferWriter<byte> bufferWriter)
        {
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { SkipValidation = true }))
            {
                writer.WriteStartObject();
                WriteTo(writer);
                writer.WriteEndObject();
                writer.Flush();
            }
        }

        /// <summary>
        /// Provides the binary representation of the key.
        /// </summary>
        public abstract ReadOnlySpan<byte> AsSpan();

        /// <summary>
        /// Creates a fresh new <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        protected abstract Signer CreateNewSigner(SignatureAlgorithm algorithm);

        /// <summary>
        /// Creates a <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        public Signer CreateSigner(SignatureAlgorithm algorithm)
        {
            if (algorithm is null)
            {
                return null;
            }

            if (_signers == null)
            {
                _signers = new CryptographicStore<Signer>();
            }

            var signers = _signers;
            if (signers.TryGetValue(algorithm.Id, out var signer))
            {
                return signer;
            }

            if (IsSupported(algorithm))
            {
                signer = CreateNewSigner(algorithm);
                if (signers.TryAdd(algorithm.Id, signer))
                {
                    return signer;
                }

                signer.Dispose();
                if (signers.TryGetValue(algorithm.Id, out signer))
                {
                    return signer;
                }

                ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
            }

            return null;
        }

        /// <summary>
        /// Releases the <see cref="Signer"/>.
        /// </summary>
        /// <param name="signer"></param>
        public void Release(Signer signer)
        {
            _signers.TryRemove(signer.Algorithm.Id);
        }

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        public KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (encryptionAlgorithm is null || algorithm is null)
            {
                return null;
            }

            if (_keyWrappers == null)
            {
                _keyWrappers = new CryptographicStore<KeyWrapper>();
            }

            var algorithmKey = encryptionAlgorithm.ComputeKey(algorithm);
            if (_keyWrappers.TryGetValue(algorithmKey, out var cachedKeyWrapper))
            {
                return cachedKeyWrapper;
            }

            if (IsSupported(algorithm))
            {
                var keyWrapper = CreateNewKeyWrapper(encryptionAlgorithm, algorithm);
                if (_keyWrappers.TryAdd(algorithmKey, keyWrapper))
                {
                    return keyWrapper;
                }

                keyWrapper.Dispose();
                if (_keyWrappers.TryGetValue(algorithmKey, out keyWrapper))
                {
                    return keyWrapper;
                }

                ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
            }

            return null;
        }

        /// <summary>
        /// Creates a fresh new <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        protected abstract KeyWrapper CreateNewKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Releases the <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="keyWrapper"></param>
        public void Release(KeyWrapper keyWrapper)
        {
            _keyWrappers.TryRemove(keyWrapper.EncryptionAlgorithm.ComputeKey(keyWrapper.Algorithm));
        }

        /// <summary>
        /// Creates a <see cref="AuthenticatedEncryptor"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for encryption.</param>
        public AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (!(encryptionAlgorithm is null))
            {
                if (_encryptors == null)
                {
                    _encryptors = new CryptographicStore<AuthenticatedEncryptor>();
                }

                var algorithmKey = encryptionAlgorithm.Id;
                if (_encryptors.TryGetValue(algorithmKey, out var encryptor))
                {
                    return encryptor;
                }

                if (IsSupported(encryptionAlgorithm))
                {
                    encryptor = CreateNewAuthenticatedEncryptor(encryptionAlgorithm);
                    if (_encryptors.TryAdd(algorithmKey, encryptor))
                    {
                        return encryptor;
                    }

                    encryptor.Dispose();
                    if (_encryptors.TryGetValue(encryptionAlgorithm.Id, out encryptor))
                    {
                        return encryptor;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            return null;
        }

        /// <summary>
        /// Creates a fresh new <see cref="AuthenticatedEncryptor"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for encryption.</param>
        protected abstract AuthenticatedEncryptor CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm);

        /// <summary>
        /// Releases the <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="encryptor"></param>
        public void Release(AuthenticatedEncryptor encryptor)
        {
            _encryptors.TryRemove(encryptor.EncryptionAlgorithm.Id);
        }

        /// <summary>
        /// Returns a new <see cref="Jwk"/> in its normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2
        /// </summary>
        /// <returns></returns>
        public byte[] Canonicalize()
        {
            using (var bufferWriter = new ArrayBufferWriter())
            {
                Canonicalize(bufferWriter);
                return bufferWriter.WrittenSpan.ToArray();
            }
        }

        /// <summary>
        /// Returns a new <see cref="Jwk"/> in its normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2
        /// </summary>
        /// <returns></returns>
        protected abstract void Canonicalize(IBufferWriter<byte> bufferWriter);

#if !NETSTANDARD2_0
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeThumbprint()
        {
            using (var hashAlgorithm = SHA256.Create())
            {
                Span<byte> hash = stackalloc byte[hashAlgorithm.HashSize >> 3];
                using (var bufferWriter = new ArrayBufferWriter())
                {
                    Canonicalize(bufferWriter);
                    hashAlgorithm.TryComputeHash(bufferWriter.WrittenSpan, hash, out int bytesWritten);
                    Debug.Assert(bytesWritten == hashAlgorithm.HashSize >> 3);
                    return Base64Url.Encode(hash);
                }
            }
        }
#else
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        public byte[] ComputeThumbprint()
        {
            using (var hashAlgorithm = SHA256.Create())
            {
                var hash = hashAlgorithm.ComputeHash(Canonicalize());
                return Base64Url.Encode(hash);
            }
        }
#endif

        /// <summary>
        /// Returns a new instance of <see cref="AsymmetricJwk"/>.
        /// </summary>
        /// <param name="certificate">A <see cref="X509Certificate2"/> that contains JSON Web Key parameters.</param>
        /// <param name="withPrivateKey">Determines if the private key must be extracted from the certificate.</param>
        public static AsymmetricJwk FromX509Certificate(X509Certificate2 certificate, bool withPrivateKey)
        {
            if (certificate == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.certificate);
            }

            AsymmetricJwk key = null;
            if (withPrivateKey)
            {
                using (var rsa = certificate.GetRSAPrivateKey())
                {
                    if (rsa != null)
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NETSTANDARD2_0
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPrivateKey())
                        {
                            if (ecdsa != null)
                            {
                                var ecParameters = ecdsa.ExportParameters(false);
                                key = new ECJwk(ecParameters);
                            }
                        }
                    }
#endif
                }
            }
            else
            {
                using (var rsa = certificate.GetRSAPublicKey())
                {
                    if (rsa != null)
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NETSTANDARD2_0
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPublicKey())
                        {
                            if (ecdsa != null)
                            {
                                var ecParameters = ecdsa.ExportParameters(false);
                                key = new ECJwk(ecParameters);
                            }
                        }
                    }
#endif
                }
            }

            if (key != null)
            {
                key.X5t = certificate.GetCertHash();
                key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
                return key;
            }

            ThrowHelper.ThrowInvalidOperationException_InvalidCertificate();
            return null;
        }

        /// <summary>
        /// Returns a new instance of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwk"/></returns>
        public static Jwk FromJson(string json)
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), true, default);
            if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                return FromJsonReader(ref reader);
            }

            ThrowHelper.ThrowArgumentException_MalformedKey();
            return null;
        }

        internal void Populate(ReadOnlySpan<byte> name, string value)
        {
            if (name.SequenceEqual(JwkParameterNames.KidUtf8))
            {
                Kid = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.X5uUtf8))
            {
                X5u = value;
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, JwtArray value)
        {
            if (name.SequenceEqual(JwkParameterNames.X5cUtf8))
            {
                _x5c = new List<byte[]>(value.Count);
                for (int i = 0; i < value.Count; i++)
                {
                    _x5c.Add((byte[])value[i].Value);
                }
            }
            else if (name.SequenceEqual(JwkParameterNames.KeyOpsUtf8))
            {
                _keyOps = new List<string>(value.Count);
                for (int i = 0; i < value.Count; i++)
                {
                    _keyOps.Add((string)value[i].Value);
                }
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, byte[] value)
        {
            if (name.SequenceEqual(JwkParameterNames.AlgUtf8))
            {
                Alg = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.UseUtf8))
            {
                Use = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.X5tS256Utf8))
            {
                X5tS256 = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.X5tUtf8))
            {
                X5t = value;
            }
        }

        internal static unsafe void PopulateEight(ref Utf8JsonReader reader, byte* pPropertyName, Jwk key)
        {
            if (*(ulong*)pPropertyName == 3906083584472266104u /* x5t#s256 */)
            {
                key.X5tS256 = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
            }
        }

        internal static unsafe void PopulateArray(ref Utf8JsonReader reader, byte* pPropertyName, int propertyLength, Jwk key)
        {
            if (propertyLength == 7 && *(uint*)pPropertyName == 1601791339u /* key_ */ && *(uint*)(pPropertyName + 3) == 1936748383 /* _ops */)
            {
                /* key_ops */
                key._keyOps = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    key._keyOps.Add(reader.GetString());
                }
            }
            else if (propertyLength == 3 && *pPropertyName == (byte)'x' && *(ushort*)(pPropertyName + 1) == 25397u)
            {
                /* x5c */
                key._x5c = new List<byte[]>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    key._x5c.Add(Convert.FromBase64String(reader.GetString()));
                }
            }
            else
            {
                JsonParser.ConsumeJsonArray(ref reader);
            }
        }

        internal static void PopulateObject(ref Utf8JsonReader reader)
        {
            JsonParser.ConsumeJsonObject(ref reader);
        }

        internal static unsafe void PopulateThree(ref Utf8JsonReader reader, byte* pPropertytName, Jwk key)
        {
            ushort* pPropertyNameShort = (ushort*)(pPropertytName + 1);
            switch (*pPropertytName)
            {
                /* alg */
                case (byte)'a' when *pPropertyNameShort == 26476u:
                    key.Alg = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
                    break;
                /* kid */
                case (byte)'k' when *pPropertyNameShort == 25705u:
                    key.Kid = reader.GetString();
                    break;
                /* use */
                case (byte)'u' when *pPropertyNameShort == 25971u:
                    key.Use = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
                    break;
                /* x5t */
                case (byte)'x' when *pPropertyNameShort == 29749u:
                    key.X5t = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                    break;
                /* x5u */
                case (byte)'x' when *pPropertyNameShort == 30005u:
                    key.X5u = reader.GetString();
                    break;

                default:
                    break;
            }
        }

        internal abstract void WriteComplementTo(Utf8JsonWriter writer);

        internal void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
            if (Kid != null)
            {
                writer.WriteString(JwkParameterNames.KidUtf8, Kid);
            }
            if (_use != null)
            {
                writer.WriteString(JwkParameterNames.UseUtf8, _use);
            }
            if (Alg != null)
            {
                writer.WriteString(JwkParameterNames.AlgUtf8, Alg);
            }
            if (_keyOps?.Count > 0)
            {
                writer.WriteStartArray(JwkParameterNames.KeyOpsUtf8);
                for (int i = 0; i < _keyOps.Count; i++)
                {
                    writer.WriteStringValue(_keyOps[i]);
                }

                writer.WriteEndArray();
            }
            if (X5t != null)
            {
                writer.WriteString(JwkParameterNames.X5tUtf8, Base64Url.Encode(X5t));
            }
            if (X5tS256 != null)
            {
                writer.WriteString(JwkParameterNames.X5tS256Utf8, Base64Url.Encode(X5tS256));
            }
            if (X5u != null)
            {
                writer.WriteString(JwkParameterNames.X5uUtf8, X5u);
            }
            if (_x5c != null && _x5c.Count > 0)
            {
                writer.WriteStartArray(JwkParameterNames.X5cUtf8);
                for (int i = 0; i < _x5c.Count; i++)
                {
                    writer.WriteStringValue(Convert.ToBase64String(_x5c[i]));
                }

                writer.WriteEndArray();
            }

            WriteComplementTo(writer);
        }

        private string DebuggerDisplay()
        {
            using (var bufferWriter = new ArrayBufferWriter())
            {
                using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
                {
                    writer.WriteStartObject();
                    WriteTo(writer);
                    writer.WriteEndObject();
                }

                var input = bufferWriter.WrittenSpan;
#if NETSTANDARD2_0
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }

        internal bool CanUseForSignature(SignatureAlgorithm signatureAlgorithm)
        {
            if (IsSigningKey)
            {
                var algorithm = SignatureAlgorithm;
                return algorithm is null || algorithm == signatureAlgorithm;
            }

            return false;
        }

        internal bool CanUseForKeyWrapping(KeyManagementAlgorithm keyManagementAlgorithm)
        {
            if (IsEncryptionKey)
            {
                var algorithm = KeyManagementAlgorithm;
                return algorithm is null || keyManagementAlgorithm == algorithm;
            }

            return false;
        }

        /// <inheritsdoc />
        public abstract bool Equals(Jwk other);

        /// <inheritsdoc />
        public virtual void Dispose()
        {
            if (_signers != null)
            {
                for (int i = 0; i < _signers.Count; i++)
                {
                    _signers[i].Dispose();
                }
            }

            if (_keyWrappers != null)
            {
                for (int i = 0; i < _keyWrappers.Count; i++)
                {
                    _keyWrappers[i].Dispose();
                }
            }

            if (_encryptors != null)
            {
                for (int i = 0; i < _encryptors.Count; i++)
                {
                    _encryptors[i].Dispose();
                }
            }
        }

        internal class NullJwk : Jwk
        {
            public override ReadOnlySpan<byte> Kty => ReadOnlySpan<byte>.Empty;

            public override int KeySizeInBits => 0;

            public override ReadOnlySpan<byte> AsSpan()
            {
                return ReadOnlySpan<byte>.Empty;
            }

            protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
            {
            }

            public override bool Equals(Jwk other)
            {
                return true;
            }

            public override bool IsSupported(SignatureAlgorithm algorithm)
            {
                return algorithm == SignatureAlgorithm.None;
            }

            public override bool IsSupported(KeyManagementAlgorithm algorithm)
            {
                return false;
            }

            public override bool IsSupported(EncryptionAlgorithm algorithm)
            {
                return false;
            }

            internal override void WriteComplementTo(Utf8JsonWriter writer)
            {
            }

            protected override KeyWrapper CreateNewKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            {
                return null;
            }

            protected override AuthenticatedEncryptor CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
            {
                return null;
            }

            protected override Signer CreateNewSigner(SignatureAlgorithm algorithm)
            {
                return Signer.None;
            }
        }
    }
}
