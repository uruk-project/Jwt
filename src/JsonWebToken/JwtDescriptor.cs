// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

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

        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> DefaultRequiredHeaderParameters = new ReadOnlyDictionary<string, JwtTokenType[]>(new Dictionary<string, JwtTokenType[]>());
        private Jwk _key;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        protected JwtDescriptor()
            : this(new HeaderDescriptor())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor"/>.
        /// </summary>
        /// <param name="header"></param>
        protected JwtDescriptor(HeaderDescriptor header)
        {
            Header = header;
        }

        /// <summary>
        /// Gets the parameters header.
        /// </summary>
        public HeaderDescriptor Header { get; }

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
        protected virtual ReadOnlyDictionary<string, JwtTokenType[]> RequiredHeaderParameters => DefaultRequiredHeaderParameters;

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
        public IReadOnlyList<string> X509CertificateChain
        {
            get => GetHeaderParameters<string>(HeaderParameters.X5c);
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
        public IReadOnlyList<string> Critical
        {
            get => GetHeaderParameters<string>(HeaderParameters.Crit);
            set => SetHeaderParameter(HeaderParameters.Crit, value);
        }

        /// <summary>
        /// Encodes the current <see cref="JwtDescriptor"/> into it <see cref="string"/> representation.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public abstract byte[] Encode(EncodingContext context);

        /// <summary>
        /// Gets the header parameter for a specified header name.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="headerName"></param>
        /// <returns></returns>
        protected T GetHeaderParameter<T>(string headerName)
        {
            if (Header.TryGetValue(headerName, out var value))
            {
                return (T)value.Value;
            }

            return default;
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="headerName"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter(string headerName, string value)
        {
            if (value != null)
            {
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName), value);
            }
            else
            {
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName));
            }
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
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName), JObject.FromObject(value));
            }
            else
            {
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName));
            }
        }

        /// <summary>
        /// Sets the header parameter for a specified header name.
        /// </summary>
        /// <param name="headerName"></param>
        /// <param name="value"></param>
        protected void SetHeaderParameter<T>(string headerName, IReadOnlyList<T> value)
        {
            if (value != null)
            {
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName), JArray.FromObject(value));
            }
            else
            {
                Header[headerName] = new JwtProperty(Encoding.UTF8.GetBytes(headerName));
            }
        }

        /// <summary>
        /// Gets the list of header parameters for a header name.
        /// </summary>
        /// <param name="headerName"></param>
        /// <returns></returns>
        protected IReadOnlyList<T> GetHeaderParameters<T>(string headerName)
        {
            if (Header.TryGetValue(headerName, out JwtProperty value))
            {
                if (value.Type == JwtTokenType.Array)
                {
                    return new ReadOnlyCollection<T>((List<T>)value.Value);
                }

                var list = new List<T> { (T)value.Value };
                return new ReadOnlyCollection<T>(list);
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
                if (!Header.TryGetValue(header.Key, out var token) || token.Type == JwtTokenType.Null)
                {
                    Errors.ThrowHeaderIsRequired(header.Key);
                }

                bool headerFound = false;
                for (int i = 0; i < header.Value.Length; i++)
                {
                    if (token.Type == header.Value[i])
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
        /// <returns></returns>
        protected string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value, Formatting.None, serializerSettings);
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
            return JsonConvert.SerializeObject(Header, Formatting.Indented, serializerSettings);
        }

#if NETCOREAPP3_0
        public static ReadOnlySequence<byte> Serialize(HeaderDescriptor value, Formatting formatting)
        {
            var bufferWriter = new BufferWriter();
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = formatting == Formatting.Indented }));

                writer.WriteStartObject();
                WriteObject(ref writer, value);
                writer.WriteEndObject();
                writer.Flush();

                return bufferWriter.GetSequence();
            }
        }

        public static ReadOnlySequence<byte> Serialize(PayloadDescriptor value)
        {
            var bufferWriter = new BufferWriter();
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = false}));

                writer.WriteStartObject();
                WriteObject(ref writer, value);
                writer.WriteEndObject();
                writer.Flush();

                return bufferWriter.GetSequence();
            }
        }

        private static void WriteArray(ref Utf8JsonWriter writer, JArray value)
        {
            for (int i = 0; i < value.Count; i++)
            {
                var token = value[i];
                switch (token.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject();
                        WriteObject(ref writer, token.Value<JObject>());
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray();
                        WriteArray(ref writer, token.Value<JArray>());
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumberValue(token.Value<long>());
                        break;
                    case JTokenType.Float:
                        writer.WriteNumberValue(token.Value<double>());
                        break;
                    case JTokenType.String:
                        writer.WriteStringValue(token.Value<string>());
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBooleanValue(token.Value<bool>());
                        break;
                    case JTokenType.Null:
                        writer.WriteNullValue();
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }

        private static void WriteObject(ref Utf8JsonWriter writer, JObject jObject)
        {
            foreach ((var key, var value) in jObject)
            {
                switch (value.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject(key);
                        WriteObject(ref writer, value.Value<JObject>());
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray(key);
                        WriteArray(ref writer, value.Value<JArray>());
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumber(key, value.Value<long>());
                        break;
                    case JTokenType.Float:
                        writer.WriteNumber(key, value.Value<double>());
                        break;
                    case JTokenType.String:
                        writer.WriteString(key, value.Value<string>(), false);
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBoolean(key, value.Value<bool>());
                        break;
                    case JTokenType.Null:
                        writer.WriteNull(key);
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }

        private static void WriteObject(ref Utf8JsonWriter writer, PayloadDescriptor payload)
        {
            foreach (var property in payload.Values)
            {
                switch (property.Type)
                {
                    case JwtTokenType.Object:
                        writer.WriteStartObject(property.Utf8Name.Span);
                        WriteObject(ref writer, (JObject)property.Value);
                        writer.WriteEndObject();
                        break;
                    case JwtTokenType.Array:
                        writer.WriteStartArray(property.Utf8Name.Span);
                        WriteArray(ref writer, (JArray)property.Value);
                        writer.WriteEndArray();
                        break;
                    case JwtTokenType.Integer:
                        writer.WriteNumber(property.Utf8Name.Span, (long)property.Value);
                        break;
                    case JwtTokenType.Float:
                        writer.WriteNumber(property.Utf8Name.Span, (double)property.Value);
                        break;
                    case JwtTokenType.String:
                        writer.WriteString(property.Utf8Name.Span, (string)property.Value, false);
                        break;
                    case JwtTokenType.Boolean:
                        writer.WriteBoolean(property.Utf8Name.Span, (bool)property.Value);
                        break;
                    case JwtTokenType.Null:
                        writer.WriteNull(property.Utf8Name.Span);
                        break;
                    default:
                        throw new JsonWriterException($"The type {property.Type} is not supported.");
                }
            }
        }

        private static void WriteObject(ref Utf8JsonWriter writer, HeaderDescriptor payload)
        {
            foreach (var property in payload.Values)
            {
                switch (property.Type)
                {
                    case JwtTokenType.Object:
                        writer.WriteStartObject(property.Utf8Name.Span);
                        WriteObject(ref writer, (JObject)property.Value);
                        writer.WriteEndObject();
                        break;
                    case JwtTokenType.Array:
                        writer.WriteStartArray(property.Utf8Name.Span);
                        WriteArray(ref writer, (JArray)property.Value);
                        writer.WriteEndArray();
                        break;
                    case JwtTokenType.Integer:
                        writer.WriteNumber(property.Utf8Name.Span, (long)property.Value);
                        break;
                    case JwtTokenType.Float:
                        writer.WriteNumber(property.Utf8Name.Span, (double)property.Value);
                        break;
                    case JwtTokenType.String:
                        writer.WriteString(property.Utf8Name.Span, (string)property.Value, false);
                        break;
                    case JwtTokenType.Boolean:
                        writer.WriteBoolean(property.Utf8Name.Span, (bool)property.Value);
                        break;
                    case JwtTokenType.Null:
                        writer.WriteNull(property.Utf8Name.Span);
                        break;
                    default:
                        throw new JsonWriterException($"The type {property.Type} is not supported.");
                }
            }
        }
#endif
    }
}
