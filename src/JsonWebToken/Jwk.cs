// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using gfoidl.Base64;
using JsonWebToken.Cryptography;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class Jwk : IEquatable<Jwk>, IDisposable
    {
#if SUPPORT_ELLIPTIC_CURVE
        private const uint EC = 17221u;
#endif
        private const uint RSA = 4281170u;
        private const uint oct = 7627631u;
        private const uint alg = 6777953u;
        private const uint use = 6648693u;
        private const uint x5t = 7615864u;
        private const uint kid = 6580587u;
        private const ulong x5t_S256 = 3906083584472266104u;
        private const uint x5c = 6501752u;
        private const uint x5u = 7681400u;
        private const ulong key_ops = 32493245967197547u;

        /// <summary>
        /// An empty <see cref="Jwk"/>.
        /// </summary>
        public static readonly Jwk Empty = new NullJwk();

        private static readonly EmptyAlgorithm EmptyAlg = new EmptyAlgorithm();

        private CryptographicStore<Signer>? _signers;
        private CryptographicStore<SignatureVerifier>? _signatureVerifiers;
        private CryptographicStore<KeyWrapper>? _keyWrappers;
        private CryptographicStore<KeyUnwrapper>? _keyUnwrappers;

        private IAlgorithm _algorithm;
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
        protected Jwk()
        {
            _algorithm = EmptyAlg;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        protected Jwk(SignatureAlgorithm alg)
        {
            if (alg is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            _algorithm = alg;
            _signatureAlgorithm = alg;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Jwk"/> class.
        /// </summary>
        /// <param name="alg"></param>
        protected Jwk(KeyManagementAlgorithm alg)
        {
            if (alg is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            _algorithm = alg;
            _keyManagementAlgorithm = alg;
        }

        /// <summary>
        /// Gets or sets the 'alg' (KeyType).
        /// </summary>
        public ReadOnlySpan<byte> Alg { get => _algorithm.Utf8Name; }

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
        public string? Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        public abstract ReadOnlySpan<byte> Kty { get; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>
        public ReadOnlySpan<byte> Use
        {
            get => _use;
            set
            {
                _use = value.ToArray();
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
                    using var certificate = new X509Certificate2(certString);
                    var key = FromX509Certificate(certificate, false);
                    key.Kid = Kid;
                    certificateChain.Add(key);
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
                    _isSigningKey = use.IsEmpty || JwkUseNames.Sig.SequenceEqual(use);
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
                    if (!alg.IsEmpty)
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
                    _isEncryptionKey = use.IsEmpty || JwkUseNames.Enc.SequenceEqual(use);
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
                    if (!alg.IsEmpty)
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
        public abstract bool SupportSignature(SignatureAlgorithm algorithm);

        internal static Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            if (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var nameSpan = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                if (nameSpan.SequenceEqual(JwkParameterNames.KtyUtf8)
                    && reader.Read() && reader.TokenType is JsonTokenType.String)
                {
                    var valueSpan = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                    switch (valueSpan.Length)
                    {
#if SUPPORT_ELLIPTIC_CURVE
                        /* EC */
                        case 2:
                            if (IntegerMarshal.ReadUInt16(valueSpan) == EC)
                            {
                                return ECJwk.FromJsonReaderFast(ref reader);
                            }
                            break;
#endif
                        case 3:
                            switch (IntegerMarshal.ReadUInt24(valueSpan))
                            {
                                /* RSA */
                                case RSA:
                                    return RsaJwk.FromJsonReaderFast(ref reader);
                                /* oct */
                                case oct:
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
                var name = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                        if (name.Length == 3)
                        {
                            // Read the 4 bytes, but use a bitmask to ignore the last byte
                            uint propertyName = IntegerMarshal.ReadUInt24(name);
                            switch (propertyName)
                            {
                                case alg:
                                    jwk.Add(new JwtProperty(WellKnownProperty.Alg, reader.ValueSpan.ToArray()));
                                    break;
                                case use:
                                    jwk.Add(new JwtProperty(name, reader.ValueSpan.ToArray()));
                                    continue;
                                case x5t:
                                    jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan .ToArray()*/)));
                                    continue;
                                case kid:
                                    jwk.Add(new JwtProperty(WellKnownProperty.Kid, reader.GetString()!));
                                    continue;
                            }
                        }
                        else if (name.Length == 8 && IntegerMarshal.ReadUInt64(name) == x5t_S256)
                        {
                            jwk.Add(new JwtProperty(name, Base64Url.Decode(reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan .ToArray()*/)));
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
                            jwk.Add(new JwtProperty(name, reader.GetDouble()));
                        }
                        break;
                    case JsonTokenType.StartArray:
                        if (name.Length == 3 && IntegerMarshal.ReadUInt24(name) == x5c)
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
                var value = reader.GetString()!;
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
            if (jwk.TryGetProperty(JwkParameterNames.KtyUtf8, out var property) && !(property.Value is null))
            {
                var kty = (string)property.Value;
                if (string.Equals(kty, "oct", StringComparison.Ordinal))
                {
                    return new SymmetricJwk(jwk);
                }
#if SUPPORT_ELLIPTIC_CURVE
                else if (string.Equals(kty, "EC", StringComparison.Ordinal))
                {
                    return ECJwk.Populate(jwk);
                }
#endif
                else if (string.Equals(kty, "RSA", StringComparison.Ordinal))
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
        public abstract bool SupportKeyManagement(KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="EncryptionAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool SupportEncryption(EncryptionAlgorithm algorithm);

        /// <summary>
        /// Returns a string that represents the <see cref="Jwk"/> in JSON.
        /// </summary>
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <summary>
        /// Serializes the <see cref="Jwk"/> into its JSON representation.
        /// </summary>
        /// <param name="bufferWriter"></param>
        public void Serialize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            WriteTo(writer);
            writer.Flush();
        }

        /// <summary>
        /// Provides the binary representation of the key.
        /// </summary>
        public abstract ReadOnlySpan<byte> AsSpan();

        /// <summary>
        /// Creates a fresh new <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        protected abstract Signer CreateSigner(SignatureAlgorithm algorithm);

        /// <summary>
        /// Creates a fresh new <see cref="SignatureVerifier"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        protected abstract SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm);

        /// <summary>
        /// Tries to provide a <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="signer">The created <see cref="Signer"/>.</param>
        /// <returns><c>true</c> if the <paramref name="signer"/> is available for the requested <paramref name="algorithm"/>; <c>false</c> otherwise.</returns>
        public bool TryGetSigner(SignatureAlgorithm? algorithm, [NotNullWhen(true)] out Signer? signer)
        {
            if (!(algorithm is null))
            {
                var signers = _signers;
                if (signers is null)
                {
                    signers = new CryptographicStore<Signer>();
                    _signers = signers;
                }
                else if (signers.TryGetValue(algorithm.Id, out signer))
                {
                    goto Found;
                }

                if (SupportSignature(algorithm))
                {
                    signer = CreateSigner(algorithm);
                    if (signers.TryAdd(algorithm.Id, signer))
                    {
                        goto Found;
                    }

                    signer.Dispose();
                    if (signers.TryGetValue(algorithm.Id, out signer))
                    {
                        goto Found;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            signer = null;
            return false;

        Found:
            return true;
        }

        /// <summary>
        /// Tries to provide a <see cref="SignatureVerifier"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="signatureVerifier">The created <see cref="SignatureVerifier"/>.</param>
        /// <returns><c>true</c> if the <paramref name="signatureVerifier"/> is available for the requested <paramref name="algorithm"/>; <c>false</c> otherwise.</returns>
        public bool TryGetSignatureVerifier(SignatureAlgorithm? algorithm, [NotNullWhen(true)] out SignatureVerifier? signatureVerifier)
        {
            if (!(algorithm is null))
            {
                var signatureVerifiers = _signatureVerifiers;
                if (signatureVerifiers is null)
                {
                    signatureVerifiers = new CryptographicStore<SignatureVerifier>();
                    _signatureVerifiers = signatureVerifiers;
                }
                else if (signatureVerifiers.TryGetValue(algorithm.Id, out signatureVerifier))
                {
                    goto Found;
                }

                if (SupportSignature(algorithm))
                {
                    signatureVerifier = CreateSignatureVerifier(algorithm);
                    if (signatureVerifiers.TryAdd(algorithm.Id, signatureVerifier))
                    {
                        goto Found;
                    }

                    signatureVerifier.Dispose();
                    if (signatureVerifiers.TryGetValue(algorithm.Id, out signatureVerifier))
                    {
                        goto Found;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            signatureVerifier = null;
            return false;

        Found:
            return true;
        }

        /// <summary>
        /// Tries to provide a <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        /// <param name="keyWrapper">The provided <see cref="KeyWrapper"/>. <c>null</c> if return <c>false</c></param>
        public bool TryGetKeyWrapper(EncryptionAlgorithm? encryptionAlgorithm, KeyManagementAlgorithm? algorithm, [NotNullWhen(true)] out KeyWrapper? keyWrapper)
        {
            if (!(encryptionAlgorithm is null) && !(algorithm is null))
            {
                var keyWrappers = _keyWrappers;
                var algorithmKey = encryptionAlgorithm.ComputeKey(algorithm);
                if (keyWrappers is null)
                {
                    keyWrappers = new CryptographicStore<KeyWrapper>();
                    _keyWrappers = keyWrappers;
                }
                else
                {
                    if (keyWrappers.TryGetValue(algorithmKey, out keyWrapper))
                    {
                        goto Found;
                    }
                }

                if (SupportKeyManagement(algorithm))
                {
                    keyWrapper = CreateKeyWrapper(encryptionAlgorithm, algorithm);
                    if (keyWrappers.TryAdd(algorithmKey, keyWrapper))
                    {
                        goto Found;
                    }

                    keyWrapper?.Dispose();
                    if (keyWrappers.TryGetValue(algorithmKey, out keyWrapper))
                    {
                        goto Found;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            keyWrapper = null;
            return false;

        Found:
            return true;
        }

        /// <summary>
        /// Tries to provide a <see cref="KeyUnwrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        /// <param name="keyUnwrapper">The provided <see cref="KeyUnwrapper"/>. <c>null</c> if return <c>false</c></param>
        public bool TryGetKeyUnwrapper(EncryptionAlgorithm? encryptionAlgorithm, KeyManagementAlgorithm? algorithm, [NotNullWhen(true)] out KeyUnwrapper? keyUnwrapper)
        {
            if (!(encryptionAlgorithm is null) && !(algorithm is null))
            {
                var keyUnwrappers = _keyUnwrappers;
                var algorithmKey = encryptionAlgorithm.ComputeKey(algorithm);
                if (keyUnwrappers is null)
                {
                    keyUnwrappers = new CryptographicStore<KeyUnwrapper>();
                    _keyUnwrappers = keyUnwrappers;
                }
                else
                {
                    if (keyUnwrappers.TryGetValue(algorithmKey, out keyUnwrapper))
                    {
                        goto Found;
                    }
                }

                if (SupportKeyManagement(algorithm))
                {
                    keyUnwrapper = CreateKeyUnwrapper(encryptionAlgorithm, algorithm);
                    if (keyUnwrappers.TryAdd(algorithmKey, keyUnwrapper))
                    {
                        goto Found;
                    }

                    keyUnwrapper?.Dispose();
                    if (keyUnwrappers.TryGetValue(algorithmKey, out keyUnwrapper))
                    {
                        goto Found;
                    }

                    ThrowHelper.ThrowInvalidOperationException_ConcurrentOperationsNotSupported();
                }
            }

            keyUnwrapper = null;
            return false;

        Found:
            return true;
        }

        /// <summary>
        /// Creates a fresh new <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        protected abstract KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Creates a fresh new <see cref="KeyUnwrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key unwrapping.</param>
        protected abstract KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Returns a new <see cref="Jwk"/> in its normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2
        /// </summary>
        /// <returns></returns>
        public byte[] Canonicalize()
        {
            int size = GetCanonicalizeSize();
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = size > Constants.MaxStackallocBytes
                                    ? stackalloc byte[size]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(size));
                Canonicalize(buffer);
                return buffer.Slice(0, size).ToArray();
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <summary>
        /// Compute the normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2, and writes it to the <paramref name="buffer"/>.
        /// </summary>
        /// <returns></returns>
        protected abstract void Canonicalize(Span<byte> buffer);

        /// <summary>
        /// Returns the required size for representing a canonicalized key.
        /// </summary>
        /// <returns></returns>
        protected abstract int GetCanonicalizeSize();

        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeThumbprint()
        {
            var thumbprint = new byte[43];
            ComputeThumbprint(thumbprint);
            return thumbprint;
        }

        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public void ComputeThumbprint(Span<byte> destination)
        {
            Debug.Assert(destination.Length == 43); // 43 => Base64Url.GetArraySizeRequiredToEncode(32)
            Span<byte> hash = stackalloc byte[32];

            int size = GetCanonicalizeSize();
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = size > Constants.MaxStackallocBytes
                                    ? stackalloc byte[size]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(size));
                Canonicalize(buffer);
                Sha256.Shared.ComputeHash(buffer, hash);
                Base64Url.Encode(hash, destination);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }            
        }

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
                using var rsa = certificate.GetRSAPrivateKey();
                if (!(rsa is null))
                {
                    var rsaParameters = rsa.ExportParameters(withPrivateKey);
                    key = RsaJwk.FromParameters(rsaParameters, false);
                }
#if SUPPORT_ELLIPTIC_CURVE
                else
                {
                    using var ecdsa = certificate.GetECDsaPrivateKey();
                    if (!(ecdsa is null))
                    {
                        var ecParameters = ecdsa.ExportParameters(withPrivateKey);
                        key = ECJwk.FromParameters(ecParameters, false);
                    }
                }
#endif
            }
            else
            {
                using var rsa = certificate.GetRSAPublicKey();
                if (!(rsa is null))
                {
                    var rsaParameters = rsa.ExportParameters(withPrivateKey);
                    key = RsaJwk.FromParameters(rsaParameters, false);
                }
#if SUPPORT_ELLIPTIC_CURVE
                else
                {
                    using var ecdsa = certificate.GetECDsaPublicKey();
                    if (!(ecdsa is null))
                    {
                        var ecParameters = ecdsa.ExportParameters(withPrivateKey);
                        key = ECJwk.FromParameters(ecParameters, false);
                    }
                }
#endif
            }

            if (key is null)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidCertificate();
            }

            key.X5t = certificate.GetCertHash();
            Span<byte> thumbprint = stackalloc byte[43];
            key.ComputeThumbprint(thumbprint);
            key.Kid = Utf8.GetString(thumbprint);
            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwk"/></returns>
        public static Jwk FromJson(string json)
        {
            byte[]? jsonToReturn = null;
            try
            {
                int length = Utf8.GetMaxByteCount(json.Length);
                Span<byte> jsonSpan = length <= Constants.MaxStackallocBytes
                            ? stackalloc byte[length]
                            : (jsonToReturn = ArrayPool<byte>.Shared.Rent(length));
                length = Utf8.GetBytes(json, jsonSpan);
                var reader = new Utf8JsonReader(jsonSpan.Slice(0, length), true, default);
                if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                {
                    return FromJsonReader(ref reader);
                }

                ThrowHelper.ThrowArgumentException_MalformedKey();
                return Empty;
            }
            finally
            {
                if (jsonToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(jsonToReturn);
                }
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="RsaJwk"/>.
        /// </summary>
        /// <param name="pem">A PEM-encoded key in PKCS1 or PKCS8 format.</param>
        /// <remarks>
        /// Support unencrypted PKCS#1 public RSA key, unencrypted PKCS#1 private RSA key, unencrypted PKCS#1 private EC key, 
        /// unencrypted PKCS#8 public RSA key, unencrypted PKCS#8 private RSA key, unencrypted PKCS#8 public EC key and unencrypted PKCS#8 private EC key. 
        /// Unencrypted PKCS#1 public EC key is not supported.
        /// Password-protected key is not supported.
        /// </remarks>
        public static AsymmetricJwk FromPem(string pem)
        {
            return PemParser.Read(pem);
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

        internal void Populate(ReadOnlySpan<byte> name, byte[] value)
        {
            if (name.SequenceEqual(JwkParameterNames.AlgUtf8))
            {
                _algorithm = new UnknownAlgorithm(value);
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
            if (IntegerMarshal.ReadUInt64(ref pPropertyName) == x5t_S256)
            {
                key.X5tS256 = Base64Url.Decode(reader.ValueSpan);
            }
        }

        internal static void PopulateEight(ref Utf8JsonReader reader, ReadOnlySpan<byte> pPropertyName, Jwk key)
        {
            if (IntegerMarshal.ReadUInt64(pPropertyName) == x5t_S256)
            {
                key.X5tS256 = Base64Url.Decode(reader.ValueSpan);
            }
        }

        internal static void PopulateArray(ref Utf8JsonReader reader, ref byte propertyNameRef, int propertyLength, Jwk key)
        {
            if (propertyLength == 7 && IntegerMarshal.ReadUInt56(ref propertyNameRef) == key_ops)
            {
                key._keyOps = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    var value = reader.GetString();
                    if (value != null)
                    {
                        key._keyOps.Add(value);
                    }
                }
            }
            else
            if (propertyLength == 3 && IntegerMarshal.ReadUInt24(ref propertyNameRef) == x5c)
            {
                key._x5c = new List<byte[]>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    var value = reader.GetString();
                    if (value != null)
                    {
                        key._x5c.Add(Convert.FromBase64String(value));
                    }
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
            uint pPropertyNameShort = IntegerMarshal.ReadUInt24(ref propertyNameRef);
            switch (pPropertyNameShort)
            {
                case alg:
                    if (SignatureAlgorithm.TryParse(ref reader, out var signatureAlgorithm))
                    {
                        key._algorithm = signatureAlgorithm;
                    }
                    else if (KeyManagementAlgorithm.TryParse(ref reader, out var keyManagementAlgorithm))
                    {
                        key._algorithm = keyManagementAlgorithm;
                    }
                    else
                    {
                        key._algorithm = new UnknownAlgorithm(reader.ValueSpan.ToArray());
                    }

                    break;
                case kid:
                    key.Kid = reader.GetString();
                    break;
                case use:
                    key.Use = reader.ValueSpan;
                    break;
                case x5t:
                    key.X5t = Base64Url.Decode(reader.ValueSpan);
                    break;
                case x5u:
                    key.X5u = reader.GetString();
                    break;

                default:
                    break;
            }
        }

        /// <summary>
        /// Writes the current <see cref="Jwk"/> into the <paramref name="writer"/>.
        /// </summary>
        /// <param name="writer"></param>
        public virtual void WriteTo(Utf8JsonWriter writer)
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
                Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(X5t.Length)];
                Base64Url.Encode(X5t, buffer);
                writer.WriteString(JwkParameterNames.X5tUtf8, buffer);
            }

            if (X5tS256 != null)
            {
                Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(X5tS256.Length)];
                int bytesWritten = Base64Url.Encode(X5tS256, buffer);
                writer.WriteString(JwkParameterNames.X5tS256Utf8, buffer.Slice(0, bytesWritten));
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
                    writer.WriteStringValue(Base64.Default.Encode(_x5c[i]));
                }

                writer.WriteEndArray();
            }
        }

        private string DebuggerDisplay()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <summary>
        /// Compute the 'kid' header parameter based on the JWK thumbprint.
        /// </summary>
        /// <param name="key"></param>
        protected static void ComputeKid(Jwk key)
        {
            Span<byte> thumbprint = stackalloc byte[43];
            key.ComputeThumbprint(thumbprint);
            key.Kid = Utf8.GetString(thumbprint);
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

        internal bool CanUseForSignature(JwtElement signatureAlgorithm)
        {
            if (IsSigningKey)
            {
                var algorithm = SignatureAlgorithm;
                return algorithm is null || signatureAlgorithm.ValueEquals(algorithm.Utf8Name);
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

        internal bool CanUseForKeyWrapping(JwtElement keyManagementAlgorithm)
        {
            if (IsEncryptionKey)
            {
                var algorithm = KeyManagementAlgorithm;
                return algorithm is null || keyManagementAlgorithm.ValueEquals(algorithm.Utf8Name);
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

            if (_keyUnwrappers != null)
            {
                _keyUnwrappers.Dispose();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteOptionalBase64UrlProperty(Utf8JsonWriter writer, Span<byte> buffer, byte[]? value, ReadOnlySpan<byte> propertyName)
        {
            if (!(value is null))
            {
                WriteBase64UrlProperty(writer, buffer, value, propertyName);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBase64UrlProperty(Utf8JsonWriter writer, Span<byte> buffer, byte[] value, ReadOnlySpan<byte> propertyName)
        {
            int bytesWritten = Base64Url.Encode(value, buffer);
            writer.WriteString(propertyName, buffer.Slice(0, bytesWritten));
        }

        internal sealed class NullJwk : Jwk
        {
            public NullJwk()
            {
                _algorithm = new EmptyAlgorithm();
            }

            public override ReadOnlySpan<byte> Kty
                => ReadOnlySpan<byte>.Empty;

            public override int KeySizeInBits
                => 0;

            public override ReadOnlySpan<byte> AsSpan()
                => ReadOnlySpan<byte>.Empty;

            protected override void Canonicalize(Span<byte> bufferWriter)
            {
            }

            protected override int GetCanonicalizeSize()
                => 0;

            public override bool Equals(Jwk? other)
                => ReferenceEquals(this, other);

            public override bool SupportSignature(SignatureAlgorithm algorithm)
                => algorithm == SignatureAlgorithm.None;

            public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
                => false;

            public override bool SupportEncryption(EncryptionAlgorithm algorithm)
                => false;

            protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
                return null;
            }

            protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
                return null;
            }

            protected override Signer CreateSigner(SignatureAlgorithm algorithm)
                => Signer.None;

            protected override SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm)
               => SignatureVerifier.None;
        }

        private sealed class UnknownAlgorithm : IAlgorithm
        {
            private readonly byte[] _alg;

            public UnknownAlgorithm(byte[] alg)
            {
                _alg = alg ?? throw new ArgumentNullException(nameof(alg));
            }

            public ReadOnlySpan<byte> Utf8Name => _alg;

            public string Name => Utf8.GetString(_alg);
        }

        private sealed class EmptyAlgorithm : IAlgorithm
        {
            public ReadOnlySpan<byte> Utf8Name => default;

            public string Name => string.Empty;
        }
    }
}
