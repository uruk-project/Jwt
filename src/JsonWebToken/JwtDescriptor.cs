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

        protected JwtDescriptor()
            : this(new Dictionary<string, object>())
        {
        }

        protected JwtDescriptor(IDictionary<string, object> header)
        {
            Header = new Dictionary<string, object>(header);
        }

        public Dictionary<string, object> Header { get; }

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

        protected virtual ReadOnlyDictionary<string, Type[]> RequiredHeaderParameters => DefaultRequiredHeaderParameters;

        public string Algorithm
        {
            get => GetHeaderParameter<string>(HeaderParameters.Alg);
            set => SetHeaderParameter(HeaderParameters.Alg, value);
        }

        public string KeyId
        {
            get => GetHeaderParameter<string>(HeaderParameters.Kid);
            set => SetHeaderParameter(HeaderParameters.Kid, value);
        }

        public string JwkSetUrl
        {
            get => GetHeaderParameter<string>(HeaderParameters.Jku);
            set => SetHeaderParameter(HeaderParameters.Jku, value);
        }

        public Jwk Jwk
        {
            get => GetHeaderParameter<Jwk>(HeaderParameters.Jwk);
            set => SetHeaderParameter(HeaderParameters.Jwk, value);
        }

        public string X509Url
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5u);
            set => SetHeaderParameter(HeaderParameters.X5u, value);
        }

        public IList<string> X509CertificateChain
        {
            get => GetHeaderParameters(HeaderParameters.X5c);
            set => SetHeaderParameter(HeaderParameters.X5c, value);
        }

        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5t);
            set => SetHeaderParameter(HeaderParameters.X5t, value);
        }

        public string Type
        {
            get => GetHeaderParameter<string>(HeaderParameters.Typ);
            set => SetHeaderParameter(HeaderParameters.Typ, value);
        }

        public string ContentType
        {
            get => GetHeaderParameter<string>(HeaderParameters.Cty);
            set => SetHeaderParameter(HeaderParameters.Cty, value);
        }

        public IList<string> Critical
        {
            get => GetHeaderParameters(HeaderParameters.Crit);
            set => SetHeaderParameter(HeaderParameters.Crit, value);
        }

        public abstract string Encode(EncodingContext context);

        protected T GetHeaderParameter<T>(string headerName)
        {
            if (Header.TryGetValue(headerName, out object value))
            {
                return (T)value;
            }

            return default;
        }

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

        protected IList<string> GetHeaderParameters(string claimType)
        {
            if (Header.TryGetValue(claimType, out object value))
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

        protected bool HasMandatoryHeaderParameter(string header)
        {
            return Header.TryGetValue(header, out var value) && value != null;
        }

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
