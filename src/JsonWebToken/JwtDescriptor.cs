// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an abstract class for representing a JWT.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor
    {
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        private static readonly ReadOnlyDictionary<string, Type[]> DefaultRequiredHeaderParameters = new ReadOnlyDictionary<string, Type[]>(new Dictionary<string, Type[]>());
        private Jwk _key;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        protected JwtDescriptor()
            : this(new Dictionary<string, object>())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        /// <param name="header"></param>
        protected JwtDescriptor(IDictionary<string, object> header)
        {
            Header = new Dictionary<string, object>(header);
        }

        /// <summary>
        /// Gets the parameters header.
        /// </summary>
        public Dictionary<string, object> Header { get; }

        /// <summary>
        /// Gets the <see cref="Jwt"/> used.
        /// </summary>
        public Jwk Key
        {
            get => _key;
            set
            {
                _key = value;
                if (value != null)
                {
                    if (value.Alg != null)
                    {
                        Algorithm = value.Alg;
                    }

                    if (value.Kid != null)
                    {
                        KeyId = value.Kid;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the required header parameters.
        /// </summary>
        protected virtual ReadOnlyDictionary<string, Type[]> RequiredHeaderParameters => DefaultRequiredHeaderParameters;

        /// <summary>
        /// Gets or sets the algorithm header.
        /// </summary>
        public string Algorithm
        {
            get => GetHeaderParameter<string>(HeaderParameters.Alg);
            set => SetHeaderParameter(HeaderParameters.Alg, value);
        }

        /// <summary>
        /// Gets or sets the key identifier header parameter.
        /// </summary>
        public string KeyId
        {
            get => GetHeaderParameter<string>(HeaderParameters.Kid);
            set => SetHeaderParameter(HeaderParameters.Kid, value);
        }

        /// <summary>
        /// Gets or sets the JWKS URL header parameter.
        /// </summary>
        public string JwkSetUrl
        {
            get => GetHeaderParameter<string>(HeaderParameters.Jku);
            set => SetHeaderParameter(HeaderParameters.Jku, value);
        }

        /// <summary>
        /// Gets or sets the JWK header parameter.
        /// </summary>
        public Jwk Jwk
        {
            get => GetHeaderParameter<Jwk>(HeaderParameters.Jwk);
            set => SetHeaderParameter(HeaderParameters.Jwk, value);
        }

        /// <summary>
        /// Gets or sets the X509 URL header parameter.
        /// </summary>
        public string X509Url
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5u);
            set => SetHeaderParameter(HeaderParameters.X5u, value);
        }

        /// <summary>
        /// Gets or sets the X509 certification chain header.
        /// </summary>
        public IList<string> X509CertificateChain
        {
            get => GetHeaderParameters(HeaderParameters.X5c);
            set => SetHeaderParameter(HeaderParameters.X5c, value);
        }

        /// <summary>
        /// Gets or sets the X509 certificate SHA-1 thumbprint header parameter.
        /// </summary>
        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5t);
            set => SetHeaderParameter(HeaderParameters.X5t, value);
        }

        /// <summary>
        /// Gets or sets the JWT type 'typ' header parameter.
        /// </summary>
        public string Type
        {
            get => GetHeaderParameter<string>(HeaderParameters.Typ);
            set => SetHeaderParameter(HeaderParameters.Typ, value);
        }

        /// <summary>
        /// Gets or sets the content type header parameter.
        /// </summary>
        public string ContentType
        {
            get => GetHeaderParameter<string>(HeaderParameters.Cty);
            set => SetHeaderParameter(HeaderParameters.Cty, value);
        }

        /// <summary>
        /// Gets or sets the critical header parameter.
        /// </summary>
        public IList<string> Critical
        {
            get => GetHeaderParameters(HeaderParameters.Crit);
            set => SetHeaderParameter(HeaderParameters.Crit, value);
        }

        /// <summary>
        /// Encodes the current <see cref="JwtDescriptor"/> into it <see cref="string"/> representation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public abstract string Encode(EncodingContext context);

        /// <summary>
        /// Gets the header parameter for a specified header name.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="headerName"></param>
        /// <returns></returns>
        protected T GetHeaderParameter<T>(string headerName)
        {
            if (Header.TryGetValue(headerName, out object value))
            {
                return (T)value;
            }

            return default;
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="headerName"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(string headerName, object value)
        {
            if (value != null)
            {
                Header[headerName] = value;
            }
            else
            {
                Header.Remove(headerName);
            }
        }

        /// <summary>
        /// Gets the list of header parameters for a header name.
        /// </summary>
        /// <param name="headerName"></param>
        /// <returns></returns>
        protected IList<string> GetHeaderParameters(string headerName)
        {
            if (Header.TryGetValue(headerName, out object value))
            {
                var list = value as IList<string>;
                if (list != null)
                {
                    return new List<string>(list);
                }
                else
                {
                    var strValue = value as string;
                    if (strValue != null)
                    {
                        return new List<string>(new[] { strValue });
                    }
                }
            }

            return null;
        }
        
        /// <summary>
        /// Validates the current <see cref="JwtDescriptor"/>.
        /// </summary>
        public virtual void Validate()
        {
            foreach (var header in RequiredHeaderParameters)
            {
                if (!Header.TryGetValue(header.Key, out object token) || token == null)
                {
                    Errors.ThrowHeaderIsRequired(header.Key);
                }

                bool headerFound = false;
                for (int i = 0; i < header.Value.Length; i++)
                {
                    if (token.GetType() == header.Value[i])
                    {
                        headerFound = true;
                        break;
                    }
                }

                if (!headerFound)
                {
                    Errors.ThrowHeaderMustBeOfType(header);
                }
            }
        }

        /// <summary>
        /// Serializes the <see cref="JwtDescriptor"/> into its JSON representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="formatting"></param>
        /// <returns></returns>
        protected string Serialize(object value, Formatting formatting)
        {
            return JsonConvert.SerializeObject(value, formatting, serializerSettings);
        }

        private string DebuggerDisplay()
        {
            return Serialize(Header, Formatting.Indented);
        }
    }
}
