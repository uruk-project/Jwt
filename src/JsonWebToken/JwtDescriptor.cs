// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an abstract class for representing a JWT.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor
    {
        private Jwk _key;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        protected JwtDescriptor()
            : this(new JwtObject(3))
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        /// <param name="header"></param>
        protected JwtDescriptor(JwtObject header)
        {
            Header = header;
        }

        /// <summary>
        /// Gets the parameters header.
        /// </summary>
        public JwtObject Header { get; }

        /// <summary>
        /// Gets the <see cref="Jwt"/> used.
        /// </summary>
        protected Jwk Key
        {
            get => _key ?? Jwk.Empty;
            set
            {
                _key = value;
                if (value != null)
                {
                    if (value.Kid != null)
                    {
                        KeyId = value.Kid;
                    }
                }

                OnKeyChanged(value);
            }
        }

        /// <summary>
        /// Called when the key is set.
        /// </summary>
        /// <param name="key"></param>
        protected abstract void OnKeyChanged(Jwk key);

        /// <summary>
        /// Gets or sets the key identifier header parameter.
        /// </summary>
        public string KeyId
        {
            get => GetHeaderParameter<string>(HeaderParameters.KidUtf8);
            set => SetHeaderParameter(HeaderParameters.KidUtf8, value);
        }

        /// <summary>
        /// Gets or sets the JWKS URL header parameter.
        /// </summary>
        public string JwkSetUrl
        {
            get => GetHeaderParameter<string>(HeaderParameters.JkuUtf8);
            set => SetHeaderParameter(HeaderParameters.JkuUtf8, value);
        }

        /// <summary>
        /// Gets or sets the JWK header parameter.
        /// </summary>
        public Jwk Jwk
        {
            get => throw new NotSupportedException(); // GetHeaderParameter<Jwk>(HeaderParameters.JwkUtf8);
            set => throw new NotSupportedException(); //SetHeaderParameter(HeaderParameters.Jwk, value);
        }

        /// <summary>
        /// Gets or sets the X509 URL header parameter.
        /// </summary>
        public string X509Url
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5uUtf8);
            set => SetHeaderParameter(HeaderParameters.X5uUtf8, value);
        }

        /// <summary>
        /// Gets or sets the X509 certification chain header.
        /// </summary>
        public List<string> X509CertificateChain
        {
            get => GetHeaderParameters<string>(HeaderParameters.X5cUtf8);
            set => SetHeaderParameter(HeaderParameters.X5cUtf8, value);
        }

        /// <summary>
        /// Gets or sets the X509 certificate SHA-1 thumbprint header parameter.
        /// </summary>
        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter<string>(HeaderParameters.X5tUtf8);
            set => SetHeaderParameter(HeaderParameters.X5tUtf8, value);
        }

        /// <summary>
        /// Gets or sets the JWT type 'typ' header parameter.
        /// </summary>
        public string Type
        {
            get => Encoding.UTF8.GetString(GetHeaderParameter<byte[]>(HeaderParameters.TypUtf8) ?? new byte[0]);
            set => SetHeaderParameter(HeaderParameters.TypUtf8, Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Gets or sets the content type header parameter.
        /// </summary>
        public string ContentType
        {
            get => GetHeaderParameter<string>(HeaderParameters.CtyUtf8);
            set => SetHeaderParameter(HeaderParameters.CtyUtf8, value);
        }

        /// <summary>
        /// Gets or sets the critical header parameter.
        /// </summary>
        public List<string> Critical
        {
            get => GetHeaderParameters<string>(HeaderParameters.CritUtf8);
            set => SetHeaderParameter(HeaderParameters.CritUtf8, value);
        }

        /// <summary>
        /// Encodes the current <see cref="JwtDescriptor"/> into it <see cref="string"/> representation.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public abstract void Encode(EncodingContext context, IBufferWriter<byte> output);

        /// <summary>
        /// Gets the header parameter for a specified header name.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected T GetHeaderParameter<T>(ReadOnlySpan<byte> utf8Name)
        {
            if (Header.TryGetValue(utf8Name, out var value))
            {
                return (T)value.Value;
            }

            return default;
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(ReadOnlySpan<byte> utf8Name, string value)
        {
            if (value != null)
            {
                Header.Replace(new JwtProperty(utf8Name, value));
            }
            else
            {
                Header.Replace(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(ReadOnlySpan<byte> utf8Name, byte[] value)
        {
            if (value != null)
            {
                Header.Replace(new JwtProperty(utf8Name, value));
            }
            else
            {
                Header.Replace(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(ReadOnlySpan<byte> utf8Name, ReadOnlySpan<byte> value)
        {
            if (!value.IsEmpty)
            {
                Header.Replace(new JwtProperty(utf8Name, value.ToArray()));
            }
            else
            {
                Header.Replace(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(string name, string value)
        {
            SetHeaderParameter(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(ReadOnlySpan<byte> utf8Name, List<string> value)
        {
            if (value != null)
            {
                Header.Replace(new JwtProperty(utf8Name, new JwtArray(value)));
            }
            else
            {
                Header.Replace(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(string name, List<string> value)
        {
            SetHeaderParameter(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Gets the list of header parameters for a header name.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected List<T> GetHeaderParameters<T>(ReadOnlySpan<byte> utf8Name)
        {
            if (Header.TryGetValue(utf8Name, out JwtProperty value))
            {
                if (value.Type == JwtTokenType.Array)
                {
                    return (List<T>)value.Value;
                }

                var list = new List<T> { (T)value.Value };
                return list;
            }

            return null;
        }

        /// <summary>
        /// Validates the current <see cref="JwtDescriptor"/>.
        /// </summary>
        public virtual void Validate()
        {
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void CheckRequiredHeader(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
            if (!Header.TryGetValue(utf8Name, out var token) || token.Type == JwtTokenType.Null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (token.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="wellKnownName"></param>
        /// <param name="type"></param>
        protected void CheckRequiredHeader(WellKnownProperty wellKnownName, JwtTokenType type)
        {
            if (!Header.TryGetValue(wellKnownName, out var token) || token.Type == JwtTokenType.Null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtProperty.GetWellKnowName(wellKnownName));
            }

            if (token.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(JwtProperty.GetWellKnowName(wellKnownName), type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required header.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void CheckRequiredHeader(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            if (!Header.TryGetValue(utf8Name, out var token) || token.Type == JwtTokenType.Null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (token.Type == types[i])
                {
                    return;
                }
            }

            ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        }
    }
}
