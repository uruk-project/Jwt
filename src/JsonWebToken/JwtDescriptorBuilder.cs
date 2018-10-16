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
        private readonly JObject _header = new JObject();
        private readonly JObject _jsonPayload = new JObject();
        private byte[] _binaryPayload;
        private string _textPayload;

        private JsonWebKey _signingKey;
        private JsonWebKey _encryptionKey;
        private TimeSpan _expireIn;
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

        public JwtDescriptorBuilder ExpiresIn(TimeSpan duration)
        {
            _expireIn = duration;
            return this;
        }

        public JwtDescriptorBuilder AddClaim(string claimName, JToken claimValue)
        {
            _jsonPayload[claimName] = claimValue;
            return this;
        }

        public JwtDescriptor Build()
        {
            if (_encryptionKey != null)
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
                    var jws = new JwsDescriptor(_jsonPayload);
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
            else
            {
                var jws = new JwsDescriptor(_header, _jsonPayload);
                if (_signingKey != null)
                {
                    jws.Key = _signingKey;
                }
                else if (!_noSignature)
                {
                    throw new InvalidOperationException("No signing key is defined.");
                }

                return jws;
            }

            throw new InvalidOperationException();
        }

        public JwtDescriptorBuilder Plaintext(string text)
        {
            _textPayload = text;
            return this;
        }

        public JwtDescriptorBuilder Binary(byte[] data)
        {
            _binaryPayload = data;
            return this;
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