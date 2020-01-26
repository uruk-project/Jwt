// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// A builder of <see cref="JwtDescriptor"/>. 
    /// </summary>
    public sealed class JwtDescriptorBuilder
    {
        private readonly JwtObject _header = new JwtObject(3);
        private JwtObject? _jsonPayload;
        private byte[]? _binaryPayload;
        private string? _textPayload;

        private Jwk? _signingKey;
        private Jwk? _encryptionKey;
        private KeyManagementAlgorithm? _keyManagementAlgorithm;
        private EncryptionAlgorithm? _encryptionAlgorithm;
        private bool _noSignature;
        private SignatureAlgorithm? _algorithm;
        private long? _expireAfter;
        private long? _notBefore;
        private bool _automaticId;
        private bool _automaticIssuedAt;

        private JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, string value)
        {
            _header.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(string name, string value)
            => AddHeader(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, long value)
        {
            _header.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(string name, long value)
            => AddHeader(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, bool value)
        {
            _header.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(string name, bool value)
            => AddHeader(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, JwtArray value)
        {
            _header.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(string name, JwtArray value)
            => AddHeader(Utf8.GetBytes(name), value);

        /// <summary>
        /// Defines the issuer.
        /// </summary>
        /// <param name="iss"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder IssuedBy(string iss)
            => AddClaim(Claims.IssUtf8, iss);

        /// <summary>
        /// Defines the expiration time.
        /// </summary>
        /// <param name="exp"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder ExpiresAt(DateTime exp)
            => AddClaim(Claims.ExpUtf8, exp.ToEpochTime());

        /// <summary>
        /// Defines the sliding expiration time.
        /// </summary>
        /// <param name="seconds"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder ExpiresAfter(long seconds)
        {
            EnsureJsonPayload();
            _expireAfter = seconds;

            return this;
        }

        /// <summary>
        /// Defines the sliding expiration time.
        /// </summary>
        /// <param name="after"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder ExpiresAfter(TimeSpan after)
            => ExpiresAfter((long)after.TotalSeconds);

        /// <summary>
        /// Defines the "not before" claim.
        /// </summary>
        /// <param name="nbf"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder NotBefore(DateTime nbf)
            => AddClaim(Claims.NbfUtf8, nbf.ToEpochTime());

        /// <summary>
        /// Defines the sliding "not before" claim.
        /// </summary>
        /// <param name="before"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder NotBefore(TimeSpan before)
            => NotBefore((long)before.TotalSeconds);

        /// <summary>
        /// Defines the sliding "not before" claim.
        /// </summary>
        /// <param name="seconds"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder NotBefore(long seconds)
        {
            EnsureJsonPayload();
            _notBefore = seconds;
            return this;
        }

        /// <summary>
        /// Defines the issuance time claim.
        /// </summary>
        /// <param name="iat"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder IssuedAt(DateTime iat)
            => AddClaim(Claims.IatUtf8, iat.ToEpochTime());

        private void EnsureJsonPayload()
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }
        }

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, string value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, string value)
            => AddClaim(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, int value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, int value)
            => AddClaim(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, double value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, double value)
            => AddClaim(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, long value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, long value)
            => AddClaim(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, float value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, float value)
            => AddClaim(Utf8.GetBytes(name), value);

        private JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, bool value)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JwtObject();
            }

            _jsonPayload.Add(new JwtProperty(utf8Name, value));
            return this;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(string name, bool value)
            => AddClaim(Utf8.GetBytes(name), value);

        /// <summary>
        /// Build the <see cref="JwtDescriptor"/>.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptor Build()
        {
            if (_encryptionKey != null)
            {
                return BuildJwe(_encryptionKey);
            }
            else
            {
                return BuilJws();
            }
        }

        private JwtDescriptor BuilJws()
        {
            if (_binaryPayload != null)
            {
                throw new InvalidOperationException($"A binary payload is defined, but not encryption key is set. Add to the call chain the method '{nameof(EncryptWith)}' with valid JWK, encryption algorithm & key management algorithm.");
            }

            if (_textPayload != null)
            {
                throw new InvalidOperationException($"A plaintext payload is defined, but not encryption key is set. Add to the call chain the method '{nameof(EncryptWith)}' with valid JWK, encryption algorithm & key management algorithm.");
            }

            if (_jsonPayload is null)
            {
                throw new InvalidOperationException("No JSON payload defined.");
            }

            JwsDescriptor jws = CreateJws(_header);

            return jws;
        }

        private JwtDescriptor BuildJwe(Jwk encryptionKey)
        {
            var alg = encryptionKey.KeyManagementAlgorithm ?? _keyManagementAlgorithm;
            if (alg is null)
            {
                throw new InvalidOperationException($"No algorithm is defined for the key management encryption. Set the 'KeyManagementAlgorithm' property on the encryption key, or specify a '{nameof(KeyManagementAlgorithm)}' to the '{nameof(EncryptWith)}' method.");
            }

            if (_binaryPayload != null)
            {
                var jwe = new BinaryJweDescriptor(_header, _binaryPayload)
                {
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = _encryptionAlgorithm,
                    Algorithm = _keyManagementAlgorithm
                };
                return jwe;
            }
            else if (_textPayload != null)
            {
                var jwe = new PlaintextJweDescriptor(_header, _textPayload)
                {
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = _encryptionAlgorithm,
                    Algorithm = _keyManagementAlgorithm
                };
                return jwe;
            }
            else if (_jsonPayload != null)
            {
                JwsDescriptor jws = CreateJws(new JwtObject(3));

                var jwe = new JweDescriptor(_header, jws)
                {
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = _encryptionAlgorithm,
                    Algorithm = _keyManagementAlgorithm
                };

                return jwe;
            }
            else
            {
                throw new InvalidOperationException("Not JSON, plaintext or binary payload is defined.");
            }
        }

        private JwsDescriptor CreateJws(JwtObject header)
        {
            var jws = new JwsDescriptor(header, _jsonPayload!);
            if (_signingKey != null)
            {
                var alg = _signingKey.SignatureAlgorithm ?? _algorithm;
                if (alg is null)
                {
                    throw new InvalidOperationException($"No algorithm is defined for the signature. Set the 'SignatureAlgorithm' property on the signing key, or specify a '{nameof(SignatureAlgorithm)}' to the '{nameof(SignWith)}' method.");
                }

                if (alg == SignatureAlgorithm.None)
                {
                    throw new InvalidOperationException($"The algorithm 'none' defined with a signing key. Specify either a signing with with a {nameof(SignatureAlgorithm)} different of 'none', or specify the {nameof(SignatureAlgorithm)} 'none' without signing key.");
                }

                jws.SigningKey = _signingKey;
                if (_algorithm != null)
                {
                    jws.Algorithm = _algorithm;
                }
            }
            else if (_noSignature)
            {
                jws.Algorithm = SignatureAlgorithm.None;
            }
            else
            {
                ThrowHelper.ThrowInvalidOperationException_NoSigningKeyDefined();
            }

            if (_automaticId)
            {
                jws.JwtId = Guid.NewGuid().ToString("N");
            }

            if (_expireAfter.HasValue)
            {
                jws.ExpirationTime = DateTime.UtcNow.AddSeconds(_expireAfter.Value);
            }

            if (_notBefore.HasValue)
            {
                jws.NotBefore = DateTime.UtcNow.AddSeconds(_notBefore.Value);
            }

            if (_automaticIssuedAt)
            {
                jws.IssuedAt = DateTime.UtcNow;
            }

            return jws;
        }

        /// <summary>
        /// Defines the plaintext as payload. 
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder PlaintextPayload(string text)
        {
            EnsurePayloadNotDefined("plaintext");

            _textPayload = text;
            return this;
        }

        /// <summary>
        /// Defines the binary data as payload.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder BinaryPayload(byte[] data)
        {
            EnsurePayloadNotDefined("binary");

            _binaryPayload = data;
            return this;
        }

        /// <summary>
        /// Defines the JSON as payload.
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder JsonPayload(JwtObject payload)
        {
            EnsurePayloadNotDefined("JSON");

            _jsonPayload = payload;
            return this;
        }

        /// <summary>
        /// Ignore the signature requirement.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptorBuilder EmptyJsonPayload()
        {
            EnsurePayloadNotDefined("JSON");

            _jsonPayload = new JwtObject(0);
            return this;
        }

        private void EnsurePayloadNotDefined(string payloadType)
        {
            if (_jsonPayload != null)
            {
                throw new InvalidOperationException($"Unable to set a {payloadType} payload. A JSON payload has already been defined.");
            }

            if (_binaryPayload != null)
            {
                throw new InvalidOperationException($"Unable to set a {payloadType} payload. A binary payload has already been defined.");
            }

            if (_textPayload != null)
            {
                throw new InvalidOperationException($"Unable to set a {payloadType} payload. A plaintext payload has already been defined.");
            }
        }

        /// <summary>
        /// Defines the key identifier.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder KeyId(string kid)
            => AddHeader(HeaderParameters.KidUtf8, kid);

        /// <summary>
        /// Defines the JWKS URL.
        /// </summary>
        /// <param name="jku"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder JwkSetUrl(string jku)
            => AddHeader(HeaderParameters.JkuUtf8, jku);

        /// <summary>
        /// Defines the 'jwk' header.
        /// </summary>
        /// <param name="jwk"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Jwk(Jwk jwk)
            => AddHeader(HeaderParameters.JwkUtf8, jwk.ToString());

        /// <summary>
        /// Defines the X509 URL.
        /// </summary>
        /// <param name="x5u"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder X509Url(string x5u)
            => AddHeader(HeaderParameters.X5uUtf8, x5u);

        /// <summary>
        /// Defines the 509 certificate chain.
        /// </summary>
        /// <param name="x5c"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder X509CertificateChain(List<string> x5c)
        {
            return AddHeader(HeaderParameters.X5cUtf8, new JwtArray(x5c));
        }

        /// <summary>
        /// Defines the X509 certificate SHA-1 thumbprint.
        /// </summary>
        /// <param name="x5t"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder X509CertificateSha1Thumbprint(string x5t)
            => AddHeader(HeaderParameters.X5tUtf8, x5t);

        /// <summary>
        /// Defines the JWT type 'typ'.
        /// </summary>
        /// <param name="typ"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Type(string typ)
            => AddHeader(HeaderParameters.TypUtf8, typ);

        /// <summary>
        /// Defines the content type 'cty'.
        /// </summary>
        /// <param name="cty"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder ContentType(string cty)
            => AddHeader(HeaderParameters.CtyUtf8, cty);

        /// <summary>
        /// Defines the critical headers.
        /// </summary>
        /// <param name="crit"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder CriticalHeaders(IEnumerable<string> crit)
            => AddHeader(HeaderParameters.CritUtf8, new JwtArray(crit.ToList()));

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for signature.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder SignWith(Jwk key)
            => SignWith(key, null);

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder SignWith(Jwk key, SignatureAlgorithm? algorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            _signingKey = key;
            _algorithm = algorithm;
            return this;
        }

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for encryption.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder EncryptWith(Jwk key, EncryptionAlgorithm encryptionAlgorithm)
            => EncryptWith(key, encryptionAlgorithm, null);

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for encryption.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="keyManagementAlgorithm"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder EncryptWith(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm? keyManagementAlgorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            _encryptionKey = key;
            _keyManagementAlgorithm = keyManagementAlgorithm;
            _encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        /// <summary>
        /// Ignore the signature requirement. It is not recommended to use unsecure JWT.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptorBuilder IgnoreSignature()
        {
            _noSignature = true;
            return this;
        }

        /// <summary>
        /// Generates a new id ('jti' claim) for each new descriptor build.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptorBuilder WithAutomaticId()
        {
            EnsureJsonPayload();
            _automaticId = true;
            return this;
        }

        /// <summary>
        /// Generate the issuance time for each new descriptor build.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptorBuilder WithAutomaticIssuedAt()
        {
            EnsureJsonPayload();
            _automaticIssuedAt = true;
            return this;
        }
    }
}