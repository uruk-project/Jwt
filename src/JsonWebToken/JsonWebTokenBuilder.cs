using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public sealed class JsonWebTokenBuilder
    {
        private readonly JObject _header = new JObject();
        private readonly JObject _jsonPayload = new JObject();
        private byte[] _binaryPayload;
        private string _textPayload;

        private JsonWebKey _signingKey;
        private JsonWebKey _encryptionKey;
        private TimeSpan _expireIn;
        private bool _noSignature;

        public JsonWebTokenBuilder AddHeader(string headerName, JToken headerValue)
        {
            _header[headerName] = headerValue;
            return this;
        }

        public JsonWebTokenBuilder IssuedBy(string iss)
        {
            return AddClaim(Claims.Iss, iss);
        }

        public JsonWebTokenBuilder Expires(DateTime exp)
        {
            return AddClaim(Claims.Exp, exp);
        }

        public JsonWebTokenBuilder ExpiresIn(TimeSpan duration)
        {
            _expireIn = duration;
            return this;
        }

        public JsonWebTokenBuilder AddClaim(string claimName, JToken claimValue)
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

        public JsonWebTokenBuilder Plaintext(string text)
        {
            _textPayload = text;
            return this;
        }

        public JsonWebTokenBuilder Binary(byte[] data)
        {
            _binaryPayload = data;
            return this;
        }

        public JsonWebTokenBuilder Algorithm(string algorithm)
        {
            return AddHeader(HeaderParameters.Alg, algorithm);
        }
        public JsonWebTokenBuilder KeyId(string kid)
        {
            return AddHeader(HeaderParameters.Kid, kid);
        }
        public JsonWebTokenBuilder JwkSetUrl(string jku)
        {
            return AddHeader(HeaderParameters.Jku, jku);
        }
        public JsonWebTokenBuilder JsonWebKey(JsonWebKey jwk)
        {
            return AddHeader(HeaderParameters.Jwk, jwk.ToString());
        }
        public JsonWebTokenBuilder X509Url(string x5u)
        {
            return AddHeader(HeaderParameters.X5u, x5u);
        }
        public JsonWebTokenBuilder X509CertificateChain(IList<string> x5c)
        {
            return AddHeader(HeaderParameters.X5c, JArray.FromObject(x5c));
        }
        public JsonWebTokenBuilder X509CertificateSha1Thumbprint(string x5t)
        {
            return AddHeader(HeaderParameters.X5t, x5t);
        }
        public JsonWebTokenBuilder Type(string typ)
        {
            return AddHeader(HeaderParameters.Typ, typ);
        }

        public JsonWebTokenBuilder ContentType(string cty)
        {
            return AddHeader(HeaderParameters.Cty, cty);
        }
        public JsonWebTokenBuilder Critical(IList<string> crit)
        {
            return AddHeader(HeaderParameters.Crit, JArray.FromObject(crit));
        }

        public JsonWebTokenBuilder SignWith(JsonWebKey jwk)
        {
            _signingKey = jwk ?? throw new ArgumentNullException(nameof(jwk));
            return this;
        }

        public JsonWebTokenBuilder EncryptWith(JsonWebKey jwk)
        {
            _encryptionKey = jwk ?? throw new ArgumentNullException(nameof(jwk));
            return this;
        }

        public JsonWebTokenBuilder IgnoreSignature()
        {
            _noSignature = true;
            return this;
        }
    }
}