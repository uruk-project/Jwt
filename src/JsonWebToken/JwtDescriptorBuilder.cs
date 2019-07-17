﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// A builder of <see cref="JwtDescriptor"/>. 
    /// </summary>
    public sealed class JwtDescriptorBuilder
    {
        private readonly JwtObject _header = new JwtObject(3);
        private JwtObject _jsonPayload;
        private byte[] _binaryPayload;
        private string _textPayload;

        private Jwk _signingKey;
        private Jwk _encryptionKey;
        private bool _noSignature;

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, string value)
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
        {
            return AddHeader(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, long value)
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
        {
            return AddHeader(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, bool value)
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
        {
            return AddHeader(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a header parameter.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddHeader(ReadOnlySpan<byte> utf8Name, JwtArray value)
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
        {
            return AddHeader(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Defines the issuer.
        /// </summary>
        /// <param name="iss"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder IssuedBy(string iss)
        {
            return AddClaim(Claims.IssUtf8, iss);
        }

        /// <summary>
        /// Defines the expiration time.
        /// </summary>
        /// <param name="exp"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Expires(DateTime exp)
        {
            return AddClaim(Claims.ExpUtf8, exp.ToEpochTime());
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, string value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlyMemory<byte> utf8Name, int value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlyMemory<byte> utf8Name, double value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlySpan<byte> utf8Name, long value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlyMemory<byte> utf8Name, float value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder AddClaim(ReadOnlyMemory<byte> utf8Name, bool value)
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
        {
            return AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Build the <see cref="JwtDescriptor"/>.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptor Build()
        {
            if (_encryptionKey != null)
            {
                return BuildJwe();
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
                throw new InvalidOperationException("A binary payload is defined, but not encryption key is set.");
            }

            if (_textPayload != null)
            {
                throw new InvalidOperationException("A plaintext payload is defined, but not encryption key is set.");
            }

            var jws = new JwsDescriptor(_header, _jsonPayload);
            if (_signingKey != null)
            {
                jws.SigningKey = _signingKey;
            }
            else if (!_noSignature)
            {
                ThrowHelper.ThrowInvalidOperationException_NoSigningKeyDefined();
            }

            return jws;
        }

        private JwtDescriptor BuildJwe()
        {
            if (_binaryPayload != null)
            {
                var jwe = new BinaryJweDescriptor(_header, _binaryPayload)
                {
                    EncryptionKey = _encryptionKey
                };
                return jwe;
            }
            else if (_textPayload != null)
            {
                var jwe = new PlaintextJweDescriptor(_header, _textPayload)
                {
                    EncryptionKey = _encryptionKey
                };
                return jwe;
            }
            else if (_jsonPayload != null)
            {
                var jws = new JwsDescriptor(new JwtObject(3), _jsonPayload);
                if (_signingKey != null)
                {
                    jws.SigningKey = _signingKey;
                }
                else if (!_noSignature)
                {
                    ThrowHelper.ThrowInvalidOperationException_NoSigningKeyDefined();
                }

                var jwe = new JweDescriptor(_header, jws)
                {
                    EncryptionKey = _encryptionKey
                };

                return jwe;
            }
            else
            {
                throw new InvalidOperationException("Not JSON, plaintext or binary payload is defined.");
            }
        }

        /// <summary>
        /// Defines the plaintext as payload. 
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Plaintext(string text)
        {
            EnsureNotDefined("plaintext");

            _textPayload = text;
            return this;
        }

        /// <summary>
        /// Defines the binary data as payload.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Binary(byte[] data)
        {
            EnsureNotDefined("binary");

            _binaryPayload = data;
            return this;
        }

        /// <summary>
        /// Defines the JSON as payload.
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Json(JwtObject payload)
        {
            EnsureNotDefined("JSON");

            _jsonPayload = payload;
            return this;
        }

        private void EnsureNotDefined(string payloadType)
        {
            if (_jsonPayload != null)
            {
                throw new InvalidOperationException($"Unable to define a {payloadType} payload. A JSON payload has already been defined.");
            }

            if (_binaryPayload != null)
            {
                throw new InvalidOperationException($"Unable to define a {payloadType} payload. A binary payload has already been defined.");
            }

            if (_textPayload != null)
            {
                throw new InvalidOperationException($"Unable to define a {payloadType} payload. A plaintext payload has already been defined.");
            }
        }

        /// <summary>
        /// Defines the algorithm 'alg'.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Algorithm(string algorithm)
        {
            return AddHeader(HeaderParameters.AlgUtf8, algorithm);
        }

        /// <summary>
        /// Defines the key identifier.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder KeyId(string kid)
        {
            return AddHeader(HeaderParameters.KidUtf8, kid);
        }

        /// <summary>
        /// Defines the JWKS URL.
        /// </summary>
        /// <param name="jku"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder JwkSetUrl(string jku)
        {
            return AddHeader(HeaderParameters.JkuUtf8, jku);
        }

        /// <summary>
        /// Defines the JWK.
        /// </summary>
        /// <param name="jwk"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Jwk(Jwk jwk)
        {
            return AddHeader(HeaderParameters.JwkUtf8, jwk.ToString());
        }

        /// <summary>
        /// Defines the X509 URL.
        /// </summary>
        /// <param name="x5u"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder X509Url(string x5u)
        {
            return AddHeader(HeaderParameters.X5uUtf8, x5u);
        }

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
        {
            return AddHeader(HeaderParameters.X5tUtf8, x5t);
        }

        /// <summary>
        /// Defines the JWT type 'typ'.
        /// </summary>
        /// <param name="typ"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Type(string typ)
        {
            return AddHeader(HeaderParameters.TypUtf8, typ);
        }

        /// <summary>
        /// Defines the content type 'cty'.
        /// </summary>
        /// <param name="cty"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder ContentType(string cty)
        {
            return AddHeader(HeaderParameters.CtyUtf8, cty);
        }

        /// <summary>
        /// Defines the critical headers.
        /// </summary>
        /// <param name="crit"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder Critical(List<string> crit)
        {
            return AddHeader(HeaderParameters.CritUtf8, new JwtArray(crit));
        }

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for signature.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder SignWith(Jwk key)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            _signingKey = key;
            return this;
        }

        /// <summary>
        /// Defines the <see cref="Jwk"/> used as key for encryption.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtDescriptorBuilder EncryptWith(Jwk key)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            _encryptionKey = key;
            return this;
        }

        /// <summary>
        /// Ignore the signature requirement.
        /// </summary>
        /// <returns></returns>
        public JwtDescriptorBuilder IgnoreSignature()
        {
            _noSignature = true;
            return this;
        }
    }
}