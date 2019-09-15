// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

        private CryptographicStore<Signer>? _signers;
        private CryptographicStore<KeyWrapper>? _keyWrappers;
        private CryptographicStore<AuthenticatedEncryptor>? _encryptors;

        private bool? _isSigningKey;
        private SignatureAlgorithm? _signatureAlgorithm;
        private bool? _isEncryptionKey;
        private KeyManagementAlgorithm? _keyManagementAlgorithm;
        private byte[]? _use;
        private IList<string>? _keyOps;
        private List<byte[]>? _x5c;

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
        public byte[]? Alg { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations).
        /// </summary>
        public IList<string>? KeyOps
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
        public string? Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        public abstract ReadOnlySpan<byte> Kty { get; }

        // TODO : Replace string by another type faster to compare (4 comparisons).
        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>
        public byte[]? Use
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
        public List<byte[]>? X5c
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
        public byte[]? X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-256 thumbprint).
        /// </summary>
        public byte[]? X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL).
        /// </summary>
        public string? X5u { get; set; }

        /// <summary>
        /// Gets the key size of <see cref="Jwk"/>.
        /// </summary>
        public abstract int KeySizeInBits { get; }

        /// <summary>
        /// Gets the X.509 certificate chain.
        /// </summary>
        public IList<Jwk>? X509CertificateChain
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

        internal SignatureAlgorithm? SignatureAlgorithm
        {
            get
            {
                if (_signatureAlgorithm is null)
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

        internal KeyManagementAlgorithm? KeyManagementAlgorithm
        {
            get
            {
                if (_keyManagementAlgorithm is null)
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

        internal static Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            if (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var nameSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                if (nameSpan.SequenceEqual(JwkParameterNames.KtyUtf8)
                    && reader.Read() && reader.TokenType is JsonTokenType.String)
                {
                    var valueSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                    switch (valueSpan.Length)
                    {
#if !NET461
                        /* EC */
                        case 2:
                            if (Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(valueSpan)) == 17221u)
                            {
                                return ECJwk.FromJsonReaderFast(ref reader);
                            }
                            break;
#endif
                        case 3:
                            switch (Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(valueSpan)) & 0x00ffffff)
                            {
                                /* RSA */
                                case 4281170u:
                                    return RsaJwk.FromJsonReaderFast(ref reader);
                                /* oct */
                                case 7627631u:
                                    return new SymmetricJwk(ref reader);
                            }
                            break;
                    }

                    ThrowHelper.ThrowNotSupportedException_Jwk(valueSpan);
                }
            }

            var jwk = new JwtObject();
            do
            {
                var name = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                        if (name.Length == 3)
                        {
                            // Read the 4 bytes, but use a bitmask to ignore the last byte
                            uint propertyName = Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffff;
                            switch (propertyName)
                            {
                                /* alg */
                                case 6777953u:
                                    jwk.Add(new JwtProperty(WellKnownProperty.Alg, reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()));
                                    break;
                                /* use */
                                case 6648693u:
                                    jwk.Add(new JwtProperty(name, reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()));
                                    continue;
                                /* x5t */
                                case 7615864u:
                                    jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray())));
                                    continue;
                                /* kid */
                                case 6580587u:
                                    jwk.Add(new JwtProperty(WellKnownProperty.Kid, reader.GetString()));
                                    continue;
                            }
                        }
                        /* x5t#S256 */
                        else if (name.Length == 8 && Unsafe.ReadUnaligned<ulong>(ref MemoryMarshal.GetReference(name)) == 3906083584472266104u)
                        {
                            jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray())));
                            continue;
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
                                ThrowHelper.ThrowFormatException_NotSupportedNumberValue(name);
                            }
                        }
                        break;
                    case JsonTokenType.StartArray:
                        // x5c
                        if (name.Length == 3 && (Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffff) == 6501752u)
                        {
                            jwk.Add(new JwtProperty(name, ReadBase64StringJsonArray(ref reader)));
                            break;
                        }

                        var array = JsonParser.ReadJsonArray(ref reader);
                        jwk.Add(new JwtProperty(name, array));
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName);

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return FromJwtObject(jwk);
        }

        private static JwtArray ReadBase64StringJsonArray(ref Utf8JsonReader reader)
        {
            var array = new JwtArray(new List<JwtValue>(2));
            while (reader.Read() && reader.TokenType is JsonTokenType.String)
            {
                var value = reader.GetString();
                array.Add(new JwtValue(Convert.FromBase64String(value)));
            }

            if (!(reader.TokenType is JsonTokenType.EndArray))
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            return array;
        }

        private static Jwk FromJwtObject(JwtObject jwk)
        {
            if (jwk.TryGetValue(JwkParameterNames.KtyUtf8, out var property) && !(property.Value is null))
            {
                ReadOnlySpan<byte> kty = Encoding.UTF8.GetBytes((string)property.Value);
                if (kty.SequenceEqual(JwkTypeNames.Octet))
                {
                    return new SymmetricJwk(jwk);
                }
#if !NET461
                else if (kty.SequenceEqual(JwkTypeNames.EllipticCurve))
                {
                    return ECJwk.Populate(jwk);
                }
#endif
                else if (kty.SequenceEqual(JwkTypeNames.Rsa))
                {
                    return RsaJwk.Populate(jwk);
                }
            }

            ThrowHelper.ThrowArgumentException_MalformedKey();
            return Jwk.Empty;
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
#if NETSTANDARD2_0 || NET461
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
            using (var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation))
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
        /// <param name="signer">The created <see cref="Signer"/>.</param>
        public bool TryCreateSigner(SignatureAlgorithm? algorithm, [NotNullWhen(true)] out Signer? signer)
        {
            if (algorithm is null)
            {
                signer = null;
                return false;
            }

            var signers = _signers;
            Signer? signer;
            if (signers is null)
            {
                signers = new CryptographicStore<Signer>();
                _signers = signers;
            }
            else if (signers.TryGetValue(algorithm.Id, out signer))
            {
                return true;
            }

            if (IsSupported(algorithm))
            {
                signer = CreateNewSigner(algorithm);
                if (signers.TryAdd(algorithm.Id, signer))
                {
                    return true;
                }

                signer.Dispose();
                if (signers.TryGetValue(algorithm.Id, out signer))
                {
                    return true;
                }

                ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
            }

            return false;
        }

        /// <summary>
        /// Releases the <see cref="Signer"/>.
        /// </summary>
        /// <param name="signer"></param>
        public void Release(Signer signer)
        {
            _signers?.TryRemove(signer.Algorithm.Id);
        }

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        public KeyWrapper? CreateKeyWrapper(EncryptionAlgorithm? encryptionAlgorithm, KeyManagementAlgorithm? algorithm)
        {
            if (encryptionAlgorithm is null || algorithm is null)
            {
                return null;
            }

            var keyWrappers = _keyWrappers;
            var algorithmKey = encryptionAlgorithm.ComputeKey(algorithm);
            if (keyWrappers is null)
            {
                keyWrappers = new CryptographicStore<KeyWrapper>();
                _keyWrappers = keyWrappers;
            }
            else
            {
                if (keyWrappers.TryGetValue(algorithmKey, out var cachedKeyWrapper))
                {
                    return cachedKeyWrapper;
                }
            }

            if (IsSupported(algorithm))
            {
                var keyWrapper = CreateNewKeyWrapper(encryptionAlgorithm, algorithm);
                if (!(keyWrapper is null))
                {
                    if (keyWrappers.TryAdd(algorithmKey, keyWrapper))
                    {
                        return keyWrapper;
                    }

                    keyWrapper?.Dispose();
                    if (keyWrappers.TryGetValue(algorithmKey, out keyWrapper))
                    {
                        return keyWrapper;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            return null;
        }

        /// <summary>
        /// Creates a fresh new <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        protected abstract KeyWrapper? CreateNewKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Releases the <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="keyWrapper"></param>
        public void Release(KeyWrapper keyWrapper)
        {
            _keyWrappers?.TryRemove(keyWrapper.EncryptionAlgorithm.ComputeKey(keyWrapper.Algorithm));
        }

        /// <summary>
        /// Creates a <see cref="AuthenticatedEncryptor"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for encryption.</param>
        public AuthenticatedEncryptor? CreateAuthenticatedEncryptor(EncryptionAlgorithm? encryptionAlgorithm)
        {
            if (!(encryptionAlgorithm is null))
            {
                var encryptors = _encryptors;
                var algorithmKey = encryptionAlgorithm.Id;
                AuthenticatedEncryptor? encryptor;
                if (encryptors is null)
                {
                    encryptors = new CryptographicStore<AuthenticatedEncryptor>();
                    _encryptors = encryptors;
                }
                else
                {
                    if (encryptors.TryGetValue(algorithmKey, out encryptor))
                    {
                        return encryptor;
                    }
                }

                if (IsSupported(encryptionAlgorithm))
                {
                    encryptor = CreateNewAuthenticatedEncryptor(encryptionAlgorithm);
                    if (!(encryptor is null))
                    {
                        if (encryptors.TryAdd(algorithmKey, encryptor))
                        {
                            return encryptor;
                        }

                        encryptor.Dispose();
                        if (encryptors.TryGetValue(encryptionAlgorithm.Id, out encryptor))
                        {
                            return encryptor;
                        }

                        ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Creates a fresh new <see cref="AuthenticatedEncryptor"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for encryption.</param>
        protected abstract AuthenticatedEncryptor? CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm);

        /// <summary>
        /// Releases the <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="encryptor"></param>
        public void Release(AuthenticatedEncryptor encryptor)
        {
            _encryptors?.TryRemove(encryptor.EncryptionAlgorithm.Id);
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

#if !NETSTANDARD2_0 && !NET461
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
            if (certificate is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.certificate);
            }

            AsymmetricJwk? key = null;
            if (withPrivateKey)
            {
                using (var rsa = certificate.GetRSAPrivateKey())
                {
                    if (!(rsa is null))
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NET461
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPrivateKey())
                        {
                            if (!(ecdsa is null))
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
                    if (!(rsa is null))
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NET461
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPublicKey())
                        {
                            if (!(ecdsa is null))
                            {
                                var ecParameters = ecdsa.ExportParameters(false);
                                key = new ECJwk(ecParameters);
                            }
                        }
                    }
#endif
                }
            }

            if (key is null)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidCertificate();
            }

            key!.X5t = certificate!.GetCertHash();
            key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
            return key;
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
            return Jwk.Empty;
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
                    var bytes = (byte[]?)value[i].Value;
                    if (!(bytes is null))
                    {
                        _x5c.Add(bytes);
                    }
                }
            }
            else if (name.SequenceEqual(JwkParameterNames.KeyOpsUtf8))
            {
                _keyOps = new List<string>(value.Count);
                for (int i = 0; i < value.Count; i++)
                {
                    var ops = (string?)value[i].Value;
                    if (!(ops is null))
                    {
                        _keyOps.Add(ops);
                    }
                }
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, byte[]? value)
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

        internal static void PopulateEight(ref Utf8JsonReader reader, ref byte pPropertyName, Jwk key)
        {
            /* x5t#S256 */
            if (Unsafe.ReadUnaligned<ulong>(ref pPropertyName) == 3906083584472266104u)
            {
                key.X5tS256 = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
            }
        }

        internal static void PopulateEight(ref Utf8JsonReader reader, ReadOnlySpan<byte> pPropertyName, Jwk key)
        {
            /* x5t#S256 */
            if (Unsafe.ReadUnaligned<ulong>(ref MemoryMarshal.GetReference(pPropertyName)) == 3906083584472266104u)
            {
                key.X5tS256 = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
            }
        }

        internal static void PopulateArray(ref Utf8JsonReader reader, ref byte propertyNameRef, int propertyLength, Jwk key)
        {
            /* key_ops */
            if (propertyLength == 7 && (Unsafe.ReadUnaligned<ulong>(ref propertyNameRef) & 0x00ffffffffffffffu) == 32493245967197547u)
            {
                key._keyOps = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    key._keyOps.Add(reader.GetString());
                }
            }
            else
            if (propertyLength == 3 && (Unsafe.ReadUnaligned<uint>(ref propertyNameRef) & 0x00ffffffu) == 6501752u)
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

        internal static void PopulateThree(ref Utf8JsonReader reader, ref byte propertyNameRef, Jwk key)
        {
            uint pPropertyNameShort = Unsafe.ReadUnaligned<uint>(ref propertyNameRef) & 0x00ffffffu;
            switch (pPropertyNameShort)
            {
                /* alg */
                case 6777953u:
                    key.Alg = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
                    break;
                /* kid */
                case 6580587u:
                    key.Kid = reader.GetString();
                    break;
                /* use */
                case 6648693u:
                    key.Use = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
                    break;
                /* x5t */
                case 7615864u:
                    key.X5t = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                    break;
                /* x5u */
                case 7681400u:
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
#if NETSTANDARD2_0 || NET461
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }

        internal bool CanUseForSignature(SignatureAlgorithm? signatureAlgorithm)
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
        public abstract bool Equals(Jwk? other);

        /// <inheritsdoc />
        public virtual void Dispose()
        {
            if (_signers != null)
            {
                _signers.Dispose();
            }

            if (_keyWrappers != null)
            {
                _keyWrappers.Dispose();
            }

            if (_encryptors != null)
            {
                _encryptors.Dispose();
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

            public override bool Equals(Jwk? other)
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

            protected override KeyWrapper? CreateNewKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            {
                return null;
            }

            protected override AuthenticatedEncryptor? CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
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
