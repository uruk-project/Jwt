// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    public static partial class JsonHeaderParser
    {
        // Headers
        private static readonly string Alg = HeaderParameters.Alg;
        private static readonly string Enc = HeaderParameters.Enc;
        private static readonly string Kid = HeaderParameters.Kid;
        private static readonly string Cty = HeaderParameters.Cty;
        private static readonly string Typ = HeaderParameters.Typ;
        private static readonly string Zip = HeaderParameters.Zip;
        private static readonly string Crit = HeaderParameters.Crit;
#if !NETSTANDARD2_0
        private static readonly string Epk = HeaderParameters.Epk;
        private static readonly string Apu = HeaderParameters.Apu;
        private static readonly string Apv = HeaderParameters.Apv;
#endif

        private static JwtHeader ReadJsonHeader(ReadOnlySpan<byte> buffer)
        {
#if !NETSTANDARD2_0
            var json = Encoding.UTF8.GetString(buffer);
#else
            var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
            using (JsonTextReader reader = new JsonTextReader(new StringReader(json)))
            {
                if (!reader.Read() || reader.TokenType != JsonToken.StartObject)
                {
                    ThrowHelper.FormatNotJson();
                }

                JwtHeader header = new JwtHeader();
                string name = null;
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonToken.PropertyName:
                            string propertyName = (string)reader.Value;
                            if (string.Equals(Alg, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Alg = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Alg, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Enc, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Enc = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Enc, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Kid, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Kid = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Kid, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Cty, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Cty = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Cty, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Typ, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Typ = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Typ, JsonToken.String);
                                }
                            }
#if !NETSTANDARD
                            else if (string.Equals(Epk, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.StartObject)
                                {
                                    header.Epk = ECJwk.FromDictionary(JsonParser.ReadJson(reader));
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Epk, JsonToken.StartObject);
                                }
                            }
                            else if (string.Equals(Apu, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Apu = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Apu, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Apv, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Apv = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Apv, JsonToken.String);
                                }
                            }
#endif
                            else if (string.Equals(Zip, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    header.Zip = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Zip, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Crit, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.StartArray)
                                {
                                    var crit = new List<string>();
                                    while (reader.Read() && reader.TokenType == JsonToken.String)
                                    {
                                        crit.Add((string)reader.Value);
                                    }

                                    if (reader.TokenType != JsonToken.EndArray)
                                    {
                                        ThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonToken.String);
                                    }

                                    header.Crit = crit;
                                }
                                else
                                {
                                    ThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonToken.StartObject);
                                }
                            }
                            else
                            {
                                name = (string)reader.Value;
                            }

                            break;
                        case JsonToken.String:
                        case JsonToken.Boolean:
                        case JsonToken.Float:
                        case JsonToken.Integer:
                            header[name] = reader.Value;
                            break;
                        case JsonToken.Null:
                            header[name] = null;
                            break;

                        case JsonToken.StartObject:
                            header[name] = JsonParser.ReadJson(reader);
                            break;
                        case JsonToken.StartArray:
                            var array = JsonParser.ReadJsonArray(reader);
                            header[name] = array;
                            break;

                        case JsonToken.EndObject:
                            break;
                        default:
                            ThrowHelper.FormatMalformedJson();
                            break;
                    }
                }

                return header;
            }
        }
    }
}
#endif
