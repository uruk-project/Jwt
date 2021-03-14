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

namespace JsonWebToken
{
    /// <summary>Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.</summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public abstract class Jwk : IDisposable, IEquatable<Jwk>
    {
        private const uint EC = 17221u;
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

#if DEBUG
        static Jwk()
        {
            Utf8.AssertMagicNumber(EC, "EC");
            Utf8.AssertMagicNumber(RSA, "RSA");
            Utf8.AssertMagicNumber(oct, "oct");
            Utf8.AssertMagicNumber(alg, "alg");
            Utf8.AssertMagicNumber(use, "use");
            Utf8.AssertMagicNumber(x5t, "x5t");
            Utf8.AssertMagicNumber(kid, "kid");
            Utf8.AssertMagicNumber(x5t_S256, "x5t#S256");
            Utf8.AssertMagicNumber(x5c, "x5c");
            Utf8.AssertMagicNumber(x5u, "x5u");
            Utf8.AssertMagicNumber(key_ops, "key_ops");
        }
#endif

        /// <summary>An empty <see cref="Jwk"/>.</summary>
        public static readonly Jwk None = new NullJwk();

        private CryptographicStore<Signer>? _signers;
        private CryptographicStore<SignatureVerifier>? _signatureVerifiers;
        private CryptographicStore<KeyWrapper>? _keyWrappers;
        private CryptographicStore<KeyUnwrapper>? _keyUnwrappers;

        private bool? _isSigningKey;
        private bool? _isEncryptionKey;
        private JsonEncodedText _alg;
        private SignatureAlgorithm? _signatureAlgorithm;
        private KeyManagementAlgorithm? _keyManagementAlgorithm;
        private JsonEncodedText _use;
        private IList<JsonEncodedText>? _keyOps;
        private List<byte[]>? _x5c;

        /// <summary>Initializes a new instance of the <see cref="Jwk"/> class.</summary>
        protected Jwk()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="Jwk"/> class.</summary>
        /// <param name="alg"></param>
        protected Jwk(SignatureAlgorithm alg)
        {
            if (alg is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            _alg = alg.Name;
            _signatureAlgorithm = alg;
        }

        /// <summary>Initializes a new instance of the <see cref="Jwk"/> class.</summary>
        /// <param name="alg"></param>
        protected Jwk(KeyManagementAlgorithm alg)
        {
            if (alg is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.algorithm);
            }

            _alg = alg.Name;
            _keyManagementAlgorithm = alg;
        }

        /// <summary>Gets or sets the 'alg' (KeyType).</summary>
        public JsonEncodedText Alg => _alg;

        /// <summary>Gets the 'key_ops' (Key Operations).</summary>
        public IList<JsonEncodedText> KeyOps
        {
            get
            {
                if (_keyOps == null)
                {
                    _keyOps = new List<JsonEncodedText>();
                }

                return _keyOps;
            }
        }

        /// <summary>Gets or sets the 'kid' (Key ID).</summary>
        public JsonEncodedText Kid { get; set; }

        /// <summary>Gets or sets the 'kty' (Key Type).</summary>
        public abstract JsonEncodedText Kty { get; }

        /// <summary>Gets or sets the 'use' (Public Key Use).</summary>
        public JsonEncodedText Use
        {
            get => _use;
            set
            {
                _use = value;
                _isSigningKey = value.EncodedUtf8Bytes.IsEmpty || JwkUseValues.Sig.Equals(value);
                _isEncryptionKey = value.EncodedUtf8Bytes.IsEmpty || JwkUseValues.Enc.Equals(value);
            }
        }

        /// <summary>Gets the 'x5c' collection (X.509 Certificate Chain).</summary>
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

        /// <summary>Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint).</summary>
        public byte[]? X5t { get; set; }

        /// <summary>Gets or sets the 'x5t#S256' (X.509 Certificate SHA-256 thumbprint).</summary>
        public byte[]? X5tS256 { get; set; }

        /// <summary>Gets or sets the 'x5u' (X.509 URL).</summary>
        public string? X5u { get; set; }

        /// <summary>Gets the key size of <see cref="Jwk"/>.</summary>
        public abstract int KeySizeInBits { get; }

        /// <summary>Gets the X.509 certificate chain.</summary>
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
                    _isSigningKey = use.EncodedUtf8Bytes.IsEmpty || JwkUseValues.Sig.Equals(use);
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
                    if (!alg.EncodedUtf8Bytes.IsEmpty)
                    {
                        SignatureAlgorithm.TryParse(alg.EncodedUtf8Bytes, out _signatureAlgorithm);
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
                    _isEncryptionKey = use.EncodedUtf8Bytes.IsEmpty || JwkUseValues.Enc.Equals(use);
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
                    if (!alg.EncodedUtf8Bytes.IsEmpty)
                    {
                        KeyManagementAlgorithm.TryParse(alg.EncodedUtf8Bytes, out _keyManagementAlgorithm);
                    }
                }

                return _keyManagementAlgorithm;
            }
        }

        /// <summary>Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.</summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool SupportSignature(SignatureAlgorithm algorithm);

        internal static Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            Utf8JsonReader restore = reader;
            if (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals(JwkParameterNames.Kty.EncodedUtf8Bytes))
                {
                    if (reader.Read() && reader.TokenType is JsonTokenType.String)
                    {
                        return ReadJwkFromJsonReader(ref reader, reader.ValueSpan);
                    }
                }
                else
                {
                    do
                    {
                        reader.Read();
                        if (IsTokenTypePrimitive(reader.TokenType))
                        {
                            reader.Read();
                        }
                        else
                        {
                            reader.Skip();
                        }

                        if (reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals(JwkParameterNames.Kty.EncodedUtf8Bytes))
                        {
                            if (reader.Read() && reader.TokenType is JsonTokenType.String)
                            {
                                var ktySpan = reader.ValueSpan;
                                reader = restore;
                                return ReadJwkFromJsonReader(ref reader, ktySpan);
                            }
                        }
                    } while (reader.TokenType == JsonTokenType.PropertyName);
                }
            }

            ThrowHelper.ThrowArgumentException_MalformedKey();
            return null;
        }

        private static bool IsTokenTypePrimitive(JsonTokenType tokenType)
            => (tokenType - JsonTokenType.String) <= (JsonTokenType.Null - JsonTokenType.String);

        private static Jwk ReadJwkFromJsonReader(ref Utf8JsonReader reader, ReadOnlySpan<byte> valueSpan)
        {
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
            return None;
        }

        /// <summary>Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.</summary>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool SupportKeyManagement(KeyManagementAlgorithm algorithm);

        /// <summary>Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.</summary>
        /// <param name="algorithm">The <see cref="EncryptionAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool SupportEncryption(EncryptionAlgorithm algorithm);

        /// <summary>Returns a string that represents the <see cref="Jwk"/> in JSON.</summary>
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

        /// <summary>Serializes the <see cref="Jwk"/> into its JSON representation.</summary>
        /// <param name="bufferWriter"></param>
        public void Serialize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, JsonSerializationBehavior.NoJsonValidation);
            WriteTo(writer);
            writer.Flush();
        }

        /// <summary>Provides the binary representation of the key.</summary>
        public abstract ReadOnlySpan<byte> AsSpan();

        /// <summary>Creates a fresh new <see cref="Signer"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        protected abstract Signer CreateSigner(SignatureAlgorithm algorithm);

        /// <summary>Creates a fresh new <see cref="SignatureVerifier"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        protected abstract SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm);

        /// <summary>Tries to provide a <see cref="Signer"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="signer">The created <see cref="Signer"/>.</param>
        /// <returns><c>true</c> if the <paramref name="signer"/> is available for the requested <paramref name="algorithm"/>; <c>false</c> otherwise.</returns>
        public bool TryGetSigner(SignatureAlgorithm? algorithm, [NotNullWhen(true)] out Signer? signer)
        {
            if (!(algorithm is null))
            {
                int algorithmId = (int)algorithm.Id;
                var signers = _signers;
                if (signers is null)
                {
                    signers = new CryptographicStore<Signer>();
                    _signers = signers;
                }
                else if (signers.TryGetValue(algorithmId, out signer))
                {
                    goto Found;
                }

                if (SupportSignature(algorithm))
                {
                    signer = CreateSigner(algorithm);
                    if (signers.TryAdd(algorithmId, signer))
                    {
                        goto Found;
                    }

                    signer.Dispose();
                    if (signers.TryGetValue(algorithmId, out signer))
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

        /// <summary>Tries to provide a <see cref="SignatureVerifier"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="signatureVerifier">The created <see cref="SignatureVerifier"/>.</param>
        /// <returns><c>true</c> if the <paramref name="signatureVerifier"/> is available for the requested <paramref name="algorithm"/>; <c>false</c> otherwise.</returns>
        public bool TryGetSignatureVerifier(SignatureAlgorithm? algorithm, [NotNullWhen(true)] out SignatureVerifier? signatureVerifier)
        {
            if (!(algorithm is null))
            {
                int algorithmId = (int)algorithm.Id;
                var signatureVerifiers = _signatureVerifiers;
                if (signatureVerifiers is null)
                {
                    signatureVerifiers = new CryptographicStore<SignatureVerifier>();
                    _signatureVerifiers = signatureVerifiers;
                }
                else if (signatureVerifiers.TryGetValue(algorithmId, out signatureVerifier))
                {
                    goto Found;
                }

                if (SupportSignature(algorithm))
                {
                    signatureVerifier = CreateSignatureVerifier(algorithm);
                    if (signatureVerifiers.TryAdd(algorithmId, signatureVerifier))
                    {
                        goto Found;
                    }

                    signatureVerifier.Dispose();
                    if (signatureVerifiers.TryGetValue(algorithmId, out signatureVerifier))
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

        /// <summary>Tries to provide a <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.</summary>
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

        /// <summary>Tries to provide a <see cref="KeyUnwrapper"/> with the current <see cref="Jwk"/> as key.</summary>
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

        /// <summary>Creates a fresh new <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        protected abstract KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>Creates a fresh new <see cref="KeyUnwrapper"/> with the current <see cref="Jwk"/> as key.</summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key unwrapping.</param>
        protected abstract KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>Returns a new <see cref="Jwk"/> in its normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2</summary>
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

        /// <summary>Compute the normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2, and writes it to the <paramref name="buffer"/>.</summary>
        /// <returns></returns>
        protected internal abstract void Canonicalize(Span<byte> buffer);

        /// <summary>Returns the required size for representing a canonicalized key.</summary>
        /// <returns></returns>
        protected internal abstract int GetCanonicalizeSize();

        /// <summary>Compute a hash as defined by https://tools.ietf.org/html/rfc7638.</summary>
        /// <returns></returns>
        public byte[] ComputeThumbprint()
        {
            var thumbprint = new byte[43];
            ComputeThumbprint(thumbprint);
            return thumbprint;
        }

        /// <summary>Compute a hash as defined by https://tools.ietf.org/html/rfc7638.</summary>
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
                Sha256.Shared.ComputeHash(buffer.Slice(0, size), hash);
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

        /// <summary>Returns a new instance of <see cref="AsymmetricJwk"/>.</summary>
        /// <param name="certificate">A <see cref="X509Certificate2"/> that contains JSON Web Key parameters.</param>
        /// <param name="withPrivateKey">Determines if the private key must be extracted from the certificate.</param>
        public static AsymmetricJwk FromX509Certificate(X509Certificate2 certificate, bool withPrivateKey)
        {
            if (certificate is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.certificate);
            }

            AsymmetricJwk? key;
            if (withPrivateKey)
            {
                if (!TryReadPrivateKeyFromX509Certificate(certificate, out key))
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidCertificate();
                }
            }
            else
            {
                if (!TryReadPublicKeyFromX509Certificate(certificate, out key))
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidCertificate();
                }
            }

            return key;
        }

        /// <summary>Tries to read a public key from a certificate and create new instance of <see cref="AsymmetricJwk"/>.</summary>
        /// <param name="certificate">A <see cref="X509Certificate2"/> that contains JSON Web Key parameters.</param>
        /// <param name="key">The key read from the certificate.</param>
        public static bool TryReadPrivateKeyFromX509Certificate(X509Certificate2 certificate, [NotNullWhen(true)] out AsymmetricJwk? key)
        {
            if (certificate is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.certificate);
            }

            key = null;
            if (!certificate.HasPrivateKey)
            {
                return false;
            }

            using var rsa = certificate.GetRSAPrivateKey();
            if (!(rsa is null))
            {
                var rsaParameters = rsa.ExportParameters(true);
                key = RsaJwk.FromParameters(rsaParameters, computeThumbprint: false);
            }
#if SUPPORT_ELLIPTIC_CURVE
            else
            {
                using var ecdsa = certificate.GetECDsaPrivateKey();
                if (!(ecdsa is null))
                {
                    var ecParameters = ecdsa.ExportParameters(true);
                    key = ECJwk.FromParameters(ecParameters, computeThumbprint: false);
                }
            }
#endif
            if (key is null)
            {
                return false;
            }

            key.X5t = certificate.GetCertHash();
            Span<byte> thumbprint = stackalloc byte[43];
            key.ComputeThumbprint(thumbprint);
            key.Kid = JsonEncodedText.Encode(thumbprint, JsonSerializationBehavior.JsonEncoder);
            return true;
        }

        /// <summary>Tries to read a public key from a certificate and create a new instance of <see cref="AsymmetricJwk"/>.</summary>
        /// <param name="certificate">A <see cref="X509Certificate2"/> that contains JSON Web Key parameters.</param>
        /// <param name="key">The key read from the certificate.</param>
        public static bool TryReadPublicKeyFromX509Certificate(X509Certificate2 certificate, [NotNullWhen(true)] out AsymmetricJwk? key)
        {
            if (certificate is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.certificate);
            }

            key = null;
            using var rsa = certificate.GetRSAPublicKey();
            if (!(rsa is null))
            {
                var rsaParameters = rsa.ExportParameters(false);
                key = RsaJwk.FromParameters(rsaParameters, computeThumbprint: false);
            }
#if SUPPORT_ELLIPTIC_CURVE
            else
            {
                using var ecdsa = certificate.GetECDsaPublicKey();
                if (!(ecdsa is null))
                {
                    var ecParameters = ecdsa.ExportParameters(false);
                    key = ECJwk.FromParameters(ecParameters, computeThumbprint: false);
                }
            }
#endif
            if (key is null)
            {
                return false;
            }

            key.X5t = certificate.GetCertHash();
            Span<byte> thumbprint = stackalloc byte[43];
            key.ComputeThumbprint(thumbprint);
            key.Kid = JsonEncodedText.Encode(thumbprint, JsonSerializationBehavior.JsonEncoder);
            return true;
        }

        /// <summary>Returns a new instance of <see cref="Jwk"/>.</summary>
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
                jsonSpan = jsonSpan.Slice(0, length);
                var reader = new Utf8JsonReader(jsonSpan, true, default);
                if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                {
                    return FromJsonReader(ref reader);
                }

                ThrowHelper.ThrowArgumentException_MalformedKey();
                return None;
            }
            finally
            {
                if (jsonToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(jsonToReturn);
                }
            }
        }

        /// <summary>Checks the validity of a JSON representing a <see cref="Jwk"/>.</summary>
        /// <param name="json">A string that may contains JSON Web Key parameters in JSON format.</param>
        /// <param name="checkSupporteValues">Defines whether the member values are supported.</param>
        /// <remarks>
        /// Verify: 
        /// <list type="bullet">
        ///   <item>JSON structure</item>
        ///   <item>'kty' validity</item>
        ///   <item>Required parameters</item>
        ///   <item>Data type of required and optional parameters</item>
        ///   <item>Consistency between 'alg' and 'kty'</item>
        ///   <item>Consistency between 'alg' and 'use'</item>
        ///   <item>Consistency between 'alg' and 'key_ops'</item>
        ///   <item>Consistency between 'use' and 'key_ops'</item>
        ///   <item>RSA parameters length</item>
        ///   <item>EC key length</item>
        ///   <item>x5t &amp; x5t#S256 length</item>
        /// </list>
        /// </remarks>
        public static void Check(string json, bool checkSupporteValues = true)
        {
            try
            {
                var document = JsonDocument.Parse(json);
                CheckRequiredStringMember(document, JwkParameterNames.Kty, out JsonElement kty);

                if (kty.ValueEquals(JwkTypeNames.Octet.EncodedUtf8Bytes))
                {
                    CheckRequiredBase64UrlMember(document, JwkParameterNames.K);
                }
                else if (kty.ValueEquals(JwkTypeNames.Rsa.EncodedUtf8Bytes))
                {
                    int keyLength = 0;
                    if (TryCheckRequiredBase64UrlMember(document, JwkParameterNames.N, out var n))
                    {
                        keyLength = Base64Url.GetArraySizeRequiredToDecode(n.GetString()!.Length) * 8;
                    }

                    if (keyLength % 256 != 0 || keyLength < 512)
                    {
                        throw new JwkCheckException(@$"Invalid key length. Must be a multiple of 256 bits, and at least 512 bits. Current key length is {keyLength}");
                    }

                    CheckRequiredBase64UrlMember(document, JwkParameterNames.E);

                    int privateRsaMembers = CheckOptionalBase64UrlMember(document, JwkParameterNames.D, keyLength);
                    privateRsaMembers |= CheckOptionalBase64UrlMember(document, JwkParameterNames.P, keyLength / 2) << 1;
                    privateRsaMembers |= CheckOptionalBase64UrlMember(document, JwkParameterNames.Q, keyLength / 2) << 2;
                    privateRsaMembers |= CheckOptionalBase64UrlMember(document, JwkParameterNames.DP, keyLength / 2) << 3;
                    privateRsaMembers |= CheckOptionalBase64UrlMember(document, JwkParameterNames.DQ, keyLength / 2) << 4;
                    privateRsaMembers |= CheckOptionalBase64UrlMember(document, JwkParameterNames.QI, keyLength / 2) << 5;
                    if (privateRsaMembers != 0 && privateRsaMembers != (1 | 2 | 4 | 8 | 16 | 32))
                    {
                        if ((privateRsaMembers & 1) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.D}' member.");
                        }

                        if ((privateRsaMembers & 2) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.P}' member.");
                        }

                        if ((privateRsaMembers & 4) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.Q}' member.");
                        }

                        if ((privateRsaMembers & 8) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.DP}' member.");
                        }

                        if ((privateRsaMembers & 16) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.DQ}' member.");
                        }

                        if ((privateRsaMembers & 32) == 0)
                        {
                            throw new JwkCheckException(@$"Missing '{JwkParameterNames.QI}' member.");
                        }
                    }
                }
#if SUPPORT_ELLIPTIC_CURVE
                else if (kty.ValueEquals(JwkTypeNames.EllipticCurve.EncodedUtf8Bytes))
                {
                    CheckRequiredStringMember(document, JwkParameterNames.Crv, out JsonElement crv);
                    if (!EllipticalCurve.TryParse(crv.GetString()!, out var c))
                    {
                        throw new JwkCheckException(@$"Invalid '{JwkParameterNames.Crv}' member. Supported values are {string.Join(",", EllipticalCurveNames.All)}.");
                    }

                    CheckRequiredBase64UrlMember(document, JwkParameterNames.X);
                    CheckRequiredBase64UrlMember(document, JwkParameterNames.Y);
                    int keySize = Math.DivRem(c.KeySizeInBits, 8, out int reminder);
                    if (reminder != 0)
                    {
                        keySize++;
                    }

                    CheckOptionalBase64UrlMember(document, JwkParameterNames.D, keySize * 8);
                }
#endif
                else
                {
                    throw new JwkCheckException($"Invalid '{JwkParameterNames.Kty}' member. Value '{kty.GetString()}' is not supported. Supported values are {string.Join(",", JwkTypeNames.All)}.");
                }

                bool hasUse = false;
                if (TryCheckOptionalStringMember(document, JwkParameterNames.Use, out var use))
                {
                    if (!use.ValueEquals(JwkUseValues.Sig.EncodedUtf8Bytes)
                        && !use.ValueEquals(JwkUseValues.Enc.EncodedUtf8Bytes))
                    {
                        throw new JwkCheckException($"Invalid '{JwkParameterNames.Use}' member.  Value '{use.GetString()}' is not supported. Supported values are {string.Join(",", JwkUseValues.All)}.");
                    }

                    hasUse = true;
                }

                bool hasKeyOps = false;
                bool hasEncryptionKeyOps = false;
                bool hasSignatureKeyOps = false;
                if (TryCheckOptionalArrayMember(document, JwkParameterNames.KeyOps, out var keyOps))
                {
                    foreach (var item in keyOps.EnumerateArray())
                    {
                        hasKeyOps = true;
                        if (item.ValueKind != JsonValueKind.String)
                        {
                            throw new JwkCheckException($"Invalid '{JwkParameterNames.KeyOps}' item. Must be of type 'String'. Value '{item.GetRawText()}' is of type '{item.ValueKind}'.");
                        }

                        if (!item.ValueEquals(JwkKeyOpsValues.Sign.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.Verify.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.WrapKey.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.UnwrapKey.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.DeriveBits.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.DeriveKey.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.Encrypt.EncodedUtf8Bytes)
                            && !item.ValueEquals(JwkKeyOpsValues.Decrypt.EncodedUtf8Bytes))
                        {
                            throw new JwkCheckException(@$"Invalid '{JwkParameterNames.KeyOps}' member. Supported values are {string.Join(",", JwkKeyOpsValues.All)}.");
                        }

                        if (item.ValueEquals(JwkKeyOpsValues.Sign.EncodedUtf8Bytes)
                            || item.ValueEquals(JwkKeyOpsValues.Verify.EncodedUtf8Bytes))
                        {
                            if (hasUse && !use.ValueEquals(JwkUseValues.Sig.EncodedUtf8Bytes))
                            {
                                throw new JwkCheckException(@$"'{JwkParameterNames.KeyOps}' value '{item.GetString()}' and '{JwkParameterNames.Use}' value '{use.GetString()}' are inconsistent.");
                            }

                            hasSignatureKeyOps = true;
                        }

                        if (item.ValueEquals(JwkKeyOpsValues.WrapKey.EncodedUtf8Bytes)
                            || item.ValueEquals(JwkKeyOpsValues.UnwrapKey.EncodedUtf8Bytes)
                            || item.ValueEquals(JwkKeyOpsValues.Encrypt.EncodedUtf8Bytes)
                            || item.ValueEquals(JwkKeyOpsValues.Decrypt.EncodedUtf8Bytes))
                        {
                            if (hasUse && !use.ValueEquals(JwkUseValues.Enc.EncodedUtf8Bytes))
                            {
                                throw new JwkCheckException(@$"'{JwkParameterNames.KeyOps}' value '{item.GetString()}' and '{JwkParameterNames.Use}' value '{use.GetString()}' are inconsistent.");
                            }

                            hasEncryptionKeyOps = true;
                        }
                    }
                }

                if (TryCheckOptionalStringMember(document, JwkParameterNames.Alg, out var alg))
                {
                    if (SignatureAlgorithm.TryParse(alg, out var signatureAlgorithm))
                    {
                        if (kty.ValueEquals(JwkTypeNames.Octet.EncodedUtf8Bytes) && signatureAlgorithm.Category != AlgorithmCategory.Hmac
                            || kty.ValueEquals(JwkTypeNames.Rsa.EncodedUtf8Bytes) && signatureAlgorithm.Category != AlgorithmCategory.Rsa
                            || kty.ValueEquals(JwkTypeNames.EllipticCurve.EncodedUtf8Bytes) && signatureAlgorithm.Category != AlgorithmCategory.EllipticCurve)
                        {
                            throw new JwkCheckException(@$"'{JwkParameterNames.Kty}' value '{kty.GetString()}' and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                        }

                        if (hasUse && !use.ValueEquals(JwkUseValues.Sig.EncodedUtf8Bytes))
                        {
                            throw new JwkCheckException(@$"'{JwkParameterNames.Use}' value '{use.GetString()}' and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                        }

                        if (hasKeyOps && !hasSignatureKeyOps)
                        {
                            throw new JwkCheckException(@$"'{JwkParameterNames.KeyOps}' value and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                        }
                    }
                    else
                    {
                        if (KeyManagementAlgorithm.TryParse(alg, out var keyManagementAlgorithm))
                        {
                            if (kty.ValueEquals(JwkTypeNames.Octet.EncodedUtf8Bytes) && (keyManagementAlgorithm.Category != AlgorithmCategory.Aes && keyManagementAlgorithm.Category != AlgorithmCategory.AesGcm && keyManagementAlgorithm.Category != AlgorithmCategory.Direct)
                              || kty.ValueEquals(JwkTypeNames.Rsa.EncodedUtf8Bytes) && keyManagementAlgorithm.Category != AlgorithmCategory.Rsa
                              || kty.ValueEquals(JwkTypeNames.EllipticCurve.EncodedUtf8Bytes) && keyManagementAlgorithm.Category != AlgorithmCategory.EllipticCurve)
                            {
                                throw new JwkCheckException(@$"'{JwkParameterNames.Kty}' value '{kty.GetString()}' and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                            }

                            if (hasUse && !use.ValueEquals(JwkUseValues.Enc.EncodedUtf8Bytes))
                            {
                                throw new JwkCheckException(@$"'{JwkParameterNames.Use}' value '{use.GetString()}' and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                            }

                            if (hasKeyOps && !hasEncryptionKeyOps)
                            {
                                throw new JwkCheckException(@$"'{JwkParameterNames.KeyOps}' value and '{JwkParameterNames.Alg}' value '{alg.GetString()}' are inconsistent.");
                            }
                        }
                        else
                        {
                            throw new JwkCheckException($"Invalid '{JwkParameterNames.Alg}' member.  Value '{alg.GetString()}' is not supported. Supported values are {string.Join(",", SignatureAlgorithm.SupportedAlgorithms.Select(a => a.Name))} for signature and  {string.Join(",", KeyManagementAlgorithm.SupportedAlgorithms.Select(a => a.Name))} for key management.");
                        }
                    }
                }

                CheckOptionalStringMember(document, JwkParameterNames.Kid);
                if (TryCheckOptionalArrayMember(document, JwkParameterNames.X5c, out var x5c))
                {
                    foreach (var item in x5c.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.String)
                        {
                            throw new JwkCheckException($"Invalid '{JwkParameterNames.X5c}' item. Must be of type 'String'. Value '{item.GetRawText()}' is of type '{item.ValueKind}'.");
                        }

                        if (IsBase64UrlString(item.GetString()!))
                        {
                            throw new JwkCheckException($"Invalid '{JwkParameterNames.X5c}' value '{item.GetString()}'. Must be a valid base64 encoded string.");
                        }
                    }
                }

                CheckOptionalBase64UrlMember(document, JwkParameterNames.X5t, 160);
                CheckOptionalBase64UrlMember(document, JwkParameterNames.X5tS256, 256);
                CheckOptionalStringMember(document, JwkParameterNames.X5u);

            }
            catch (JsonException e)
            {
                throw new JwkCheckException("Malformed JSON. See inner exception for details.", e);
            }

            static void CheckRequiredBase64UrlMember(JsonDocument document, JsonEncodedText memberName)
            {
                if (!document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out var value))
                {
                    throw new JwkCheckException($"Missing '{memberName}' member.");
                }
                if (value.ValueKind != JsonValueKind.String)
                {
                    throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type 'String'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                }
                else if (!IsBase64String(value.GetString()!))
                {
                    throw new JwkCheckException($"Invalid '{memberName}' member. Must be a base64-URL encoded string.");
                }
            }

            static bool TryCheckRequiredBase64UrlMember(JsonDocument document, JsonEncodedText memberName, out JsonElement value)
            {
                if (document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out value))
                {
                    if (value.ValueKind != JsonValueKind.String)
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type 'String'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                    }
                    else if (!IsBase64UrlString(value.GetString()!))
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be a base64-URL encoded string.");
                    }

                    return true;
                }

                value = default;
                return false;
            }

            static unsafe bool IsBase64UrlString(string value)
            {
                int length = value.Length;
                for (int i = 0; i < length; i++)
                {
                    if (!IsValidChar(value[i]))
                    {
                        return false;
                    }
                }

                return true;

                static bool IsValidChar(char value)
                {
                    if (value > byte.MaxValue)
                    {
                        return false;
                    }

                    byte byteValue = (byte)value;

                    // 1-9
                    if (byteValue >= 48 && byteValue <= 57)
                    {
                        return true;
                    }

                    // + or /
                    if (byteValue == 45 || byteValue == 95)
                    {
                        return true;
                    }

                    // a-z or A-Z
                    byteValue |= 0x20;
                    if (byteValue >= 97 && byteValue <= 122)
                    {
                        return true;
                    }

                    return false;
                }
            }

            static unsafe bool IsBase64String(string value)
            {
                int length = value.Length;
                for (int i = 0; i < length; i++)
                {
                    char c = value[i];
                    if (!IsValidChar(c))
                    {
                        if (c != '=' || i < length - 2)
                        {
                            return false;
                        }
                    }
                }

                return true;

                static bool IsValidChar(char value)
                {
                    if (value > byte.MaxValue)
                    {
                        return false;
                    }

                    byte byteValue = (byte)value;

                    // 1-9
                    if (byteValue >= 48 && byteValue <= 57)
                    {
                        return true;
                    }

                    // + or /
                    if (byteValue == 43 || byteValue == 47)
                    {
                        return true;
                    }

                    // a-z or A-Z
                    byteValue |= 0x20;
                    if (byteValue >= 97 && byteValue <= 122)
                    {
                        return true;
                    }

                    return false;
                }
            }

            static int CheckOptionalBase64UrlMember(JsonDocument document, JsonEncodedText memberName, int length)
            {
                if (document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out var value))
                {
                    if (value.ValueKind != JsonValueKind.String)
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type 'String'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                    }

                    string s = value.GetString()!;
                    if (!IsBase64UrlString(s))
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be a base64-URL encoded string.");
                    }

                    int currentLength = Base64Url.GetArraySizeRequiredToDecode(s.Length) * 8;
                    if (length != 0 && length != currentLength)
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be a base64-URL encoded string with a length of {length}. Current length is {currentLength}.");
                    }

                    return 1;
                }

                return 0;
            }

            static void CheckRequiredStringMember(JsonDocument document, JsonEncodedText memberName, out JsonElement value)
            {
                if (!document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out value))
                {
                    throw new JwkCheckException($"Missing '{memberName}' member.");
                }

                if (value.ValueKind != JsonValueKind.String)
                {
                    throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type 'String'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                }
            }

            static void CheckOptionalStringMember(JsonDocument document, JsonEncodedText memberName)
                => CheckOptionalMember(document, memberName, JsonValueKind.String);

            static bool TryCheckOptionalArrayMember(JsonDocument document, JsonEncodedText memberName, out JsonElement value)
                => TryCheckOptionalMember(document, memberName, JsonValueKind.Array, out value);

            static bool TryCheckOptionalStringMember(JsonDocument document, JsonEncodedText memberName, out JsonElement value)
                => TryCheckOptionalMember(document, memberName, JsonValueKind.String, out value);

            static bool TryCheckOptionalMember(JsonDocument document, JsonEncodedText memberName, JsonValueKind type, out JsonElement value)
            {
                if (document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out value))
                {
                    if (value.ValueKind != type)
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type '{type}'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                    }

                    return true;
                }

                return false;
            }

            static void CheckOptionalMember(JsonDocument document, JsonEncodedText memberName, JsonValueKind type)
            {
                if (document.RootElement.TryGetProperty(memberName.EncodedUtf8Bytes, out var value))
                {
                    if (value.ValueKind != type)
                    {
                        throw new JwkCheckException($"Invalid '{memberName}' member. Must be of type '{type}'. Value '{value.GetRawText()}' is of type '{value.ValueKind}'.");
                    }
                }
            }
        }

        /// <summary>Returns a new instance of <see cref="RsaJwk"/>.</summary>
        /// <param name="pem">A PEM-encoded key in PKCS1 or PKCS8 format.</param>
        /// <remarks>
        /// Support unencrypted PKCS#1 public RSA key, unencrypted PKCS#1 private RSA key, unencrypted PKCS#1 private EC key, 
        /// unencrypted PKCS#8 public RSA key, unencrypted PKCS#8 private RSA key, unencrypted PKCS#8 public EC key and unencrypted PKCS#8 private EC key. 
        /// Unencrypted PKCS#1 public EC key is not supported.
        /// Password-protected key is not supported.
        /// </remarks>
        public static AsymmetricJwk FromPem(string pem)
            => PemParser.Read(pem);

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
                key._keyOps = new List<JsonEncodedText>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType != JsonTokenType.StartArray)
                    {
                        key._keyOps.Add(JsonEncodedText.Encode(reader.ValueSpan, JsonSerializationBehavior.JsonEncoder));
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
            => JsonParser.ConsumeJsonObject(ref reader);

        internal static void PopulateThree(ref Utf8JsonReader reader, ref byte propertyNameRef, Jwk key)
        {
            uint pPropertyNameShort = IntegerMarshal.ReadUInt24(ref propertyNameRef);
            switch (pPropertyNameShort)
            {
                case alg:
                    if (SignatureAlgorithm.TryParse(ref reader, out var signatureAlgorithm))
                    {
                        key._alg = signatureAlgorithm.Name;
                    }
                    else if (KeyManagementAlgorithm.TryParse(ref reader, out var keyManagementAlgorithm))
                    {
                        key._alg = keyManagementAlgorithm.Name;
                    }
                    else
                    {
                        key._alg = JsonEncodedText.Encode(reader.ValueSpan, JsonSerializationBehavior.JsonEncoder);
                    }

                    break;
                case kid:
                    key.Kid = JsonEncodedText.Encode(reader.ValueSpan, JsonSerializationBehavior.JsonEncoder);
                    break;
                case use:
                    key.Use = JsonEncodedText.Encode(reader.ValueSpan, JsonSerializationBehavior.JsonEncoder);
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

        /// <summary>Writes the current <see cref="Jwk"/> into the <paramref name="writer"/>.</summary>
        /// <param name="writer"></param>
        public virtual void WriteTo(Utf8JsonWriter writer)
        {
            // Write the 'kty' first as it easier to recognize the JWK
            writer.WriteString(JwkParameterNames.Kty, Kty);
            if (!Kid.EncodedUtf8Bytes.IsEmpty)
            {
                writer.WriteString(JwkParameterNames.Kid, Kid);
            }

            if (!_use.EncodedUtf8Bytes.IsEmpty)
            {
                writer.WriteString(JwkParameterNames.Use, _use);
            }

            if (!_alg.EncodedUtf8Bytes.IsEmpty)
            {
                writer.WriteString(JwkParameterNames.Alg, Alg);
            }

            if (_keyOps?.Count > 0)
            {
                writer.WriteStartArray(JwkParameterNames.KeyOps);
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
                writer.WriteString(JwkParameterNames.X5t, buffer);
            }

            if (X5tS256 != null)
            {
                Span<byte> buffer = stackalloc byte[Base64Url.GetArraySizeRequiredToEncode(X5tS256.Length)];
                int bytesWritten = Base64Url.Encode(X5tS256, buffer);
                writer.WriteString(JwkParameterNames.X5tS256, buffer.Slice(0, bytesWritten));
            }

            if (X5u != null)
            {
                writer.WriteString(JwkParameterNames.X5u, X5u);
            }

            if (_x5c != null && _x5c.Count > 0)
            {
                writer.WriteStartArray(JwkParameterNames.X5c);
                for (int i = 0; i < _x5c.Count; i++)
                {
                    writer.WriteStringValue(Base64.Default.Encode(_x5c[i]));
                }

                writer.WriteEndArray();
            }
        }

        /// <summary>Compute the 'kid' header parameter based on the JWK thumbprint.</summary>
        /// <param name="key"></param>
        protected static void ComputeKid(Jwk key)
        {
            Span<byte> thumbprint = stackalloc byte[43];
            key.ComputeThumbprint(thumbprint);
            key.Kid = JsonEncodedText.Encode(thumbprint, JsonSerializationBehavior.JsonEncoder);
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
        public virtual void Dispose()
        {
            GC.SuppressFinalize(this);
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
        internal static void WriteOptionalBase64UrlProperty(Utf8JsonWriter writer, Span<byte> buffer, byte[]? value, JsonEncodedText propertyName)
        {
            if (!(value is null))
            {
                WriteBase64UrlProperty(writer, buffer, value, propertyName);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteBase64UrlProperty(Utf8JsonWriter writer, Span<byte> buffer, byte[] value, JsonEncodedText propertyName)
        {
            int bytesWritten = Base64Url.Encode(value, buffer);
            writer.WriteString(propertyName, buffer.Slice(0, bytesWritten));
        }

        private string GetDebuggerDisplay()
            => ToString();

        /// <inheritdoc/>
        public abstract bool Equals(Jwk? other);

        internal sealed class NullJwk : Jwk
        {
            public override JsonEncodedText Kty
                => default;

            public override int KeySizeInBits
                => 0;

            public override ReadOnlySpan<byte> AsSpan()
                => ReadOnlySpan<byte>.Empty;

            protected internal override void Canonicalize(Span<byte> bufferWriter)
            {
            }

            protected internal override int GetCanonicalizeSize()
                => 0;

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

            public override void WriteTo(Utf8JsonWriter writer)
            {
                writer.WriteStartObject();
                writer.WriteEndObject();
            }

            public override bool Equals(Jwk? other)
                => false;
        }
    }
}
