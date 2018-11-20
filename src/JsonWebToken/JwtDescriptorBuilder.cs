// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// A builder of <see cref="JwtDescriptor"/>. 
    /// </summary>
    public sealed class JwtDescriptorBuilder
    {
        private readonly IDictionary<string, object> _header = new Dictionary<string, object>();
        private JObject _jsonPayload;
        private byte[] _binaryPayload;
        private string _textPayload;

        private JsonWebKey _signingKey;
        private JsonWebKey _encryptionKey;
        private bool _noSignature;
        
        public JwtDescriptorBuilder AddHeader(string headerName, JToken headerValue)
        {
            _header[headerName] = headerValue;
            return this;
        }

        public JwtDescriptorBuilder IssuedBy(string iss)
        {
            return AddClaim(Claims.Iss, iss);
        }

        public JwtDescriptorBuilder Expires(DateTime exp)
        {
            return AddClaim(Claims.Exp, exp);
        }

        public JwtDescriptorBuilder AddClaim(string claimName, JToken claimValue)
        {
            if (_jsonPayload == null)
            {
                _jsonPayload = new JObject();
            }

            _jsonPayload[claimName] = claimValue;
            return this;
        }

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
                jws.Key = _signingKey;
            }
            else if (!_noSignature)
            {
                Errors.ThrowNoSigningKeyDefined();
            }

            return jws;
        }

        private JwtDescriptor BuildJwe()
        {
            if (_binaryPayload != null)
            {
                var jwe = new BinaryJweDescriptor(_header, _binaryPayload)
                {
                    Key = _encryptionKey
                };
                return jwe;
            }
            else if (_textPayload != null)
            {
                var jwe = new PlaintextJweDescriptor(_header, _textPayload)
                {
                    Key = _encryptionKey
                };
                return jwe;
            }
            else
            {
                var jws = new JwsDescriptor(new Dictionary<string, object>(), _jsonPayload);
                if (_signingKey != null)
                {
                    jws.Key = _signingKey;
                }
                else if (!_noSignature)
                {
                    Errors.ThrowNoSigningKeyDefined();
                }

                var jwe = new JweDescriptor(_header, jws)
                {
                    Key = _encryptionKey
                };

                return jwe;
            }
        }

        public JwtDescriptorBuilder Plaintext(string text)
        {
            EnsureNotDefined("plaintext");

            _textPayload = text;
            return this;
        }

        public JwtDescriptorBuilder Binary(byte[] data)
        {
            EnsureNotDefined("binary");

            _binaryPayload = data;
            return this;
        }

        public JwtDescriptorBuilder Json(JObject payload)
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

        public JwtDescriptorBuilder Algorithm(string algorithm)
        {
            return AddHeader(HeaderParameters.Alg, algorithm);
        }

        public JwtDescriptorBuilder KeyId(string kid)
        {
            return AddHeader(HeaderParameters.Kid, kid);
        }

        public JwtDescriptorBuilder JwkSetUrl(string jku)
        {
            return AddHeader(HeaderParameters.Jku, jku);
        }

        public JwtDescriptorBuilder JsonWebKey(JsonWebKey jwk)
        {
            return AddHeader(HeaderParameters.Jwk, jwk.ToString());
        }

        public JwtDescriptorBuilder X509Url(string x5u)
        {
            return AddHeader(HeaderParameters.X5u, x5u);
        }

        public JwtDescriptorBuilder X509CertificateChain(IList<string> x5c)
        {
            return AddHeader(HeaderParameters.X5c, JArray.FromObject(x5c));
        }

        public JwtDescriptorBuilder X509CertificateSha1Thumbprint(string x5t)
        {
            return AddHeader(HeaderParameters.X5t, x5t);
        }

        public JwtDescriptorBuilder Type(string typ)
        {
            return AddHeader(HeaderParameters.Typ, typ);
        }

        public JwtDescriptorBuilder ContentType(string cty)
        {
            return AddHeader(HeaderParameters.Cty, cty);
        }

        public JwtDescriptorBuilder Critical(IList<string> crit)
        {
            return AddHeader(HeaderParameters.Crit, JArray.FromObject(crit));
        }

        public JwtDescriptorBuilder SignWith(JsonWebKey jwk)
        {
            _signingKey = jwk ?? throw new ArgumentNullException(nameof(jwk));
            return this;
        }

        public JwtDescriptorBuilder EncryptWith(JsonWebKey jwk)
        {
            _encryptionKey = jwk ?? throw new ArgumentNullException(nameof(jwk));
            return this;
        }

        public JwtDescriptorBuilder IgnoreSignature()
        {
            _noSignature = true;
            return this;
        }
    }
}