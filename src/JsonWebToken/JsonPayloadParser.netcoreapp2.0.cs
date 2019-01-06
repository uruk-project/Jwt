// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    public static partial class JsonPayloadParser
    {
        // Claims
        private static readonly string Exp = Claims.Exp;
        private static readonly string Jti = Claims.Jti;
        private static readonly string Nbf = Claims.Nbf;
        private static readonly string Iss = Claims.Iss;
        private static readonly string Iat = Claims.Iat;
        private static readonly string Aud = Claims.Aud;
        private static readonly string Sub = Claims.Sub;

        private static JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
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

                JwtPayload payload = new JwtPayload();
                string name = null;
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonToken.PropertyName:
                            var propertyName = (string)reader.Value;
                            if (string.Equals(Iss, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    payload.Iss = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Iss, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Aud, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read())
                                {
                                    if (reader.TokenType == JsonToken.String)
                                    {
                                        payload.Aud = new List<string> { (string)reader.Value };
                                    }
                                    else if (reader.TokenType == JsonToken.StartArray)
                                    {
                                        var aud = new List<string>(2);
                                        while (reader.Read() && reader.TokenType == JsonToken.String)
                                        {
                                            aud.Add((string)reader.Value);
                                        }

                                        if (reader.TokenType != JsonToken.EndArray)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Aud, JsonToken.String);
                                        }

                                        payload.Aud = aud;
                                    }
                                    else if (reader.TokenType != JsonToken.Null)
                                    {
                                        ThrowHelper.FormatMalformedJson(Claims.Aud, JsonToken.String);
                                    }
                                }
                                else
                                {
                                    ThrowHelper.FormatMalformedJson();
                                }
                            }
                            else if (string.Equals(Exp, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.Integer)
                                {
                                    payload.Exp = (long)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Exp, JsonToken.Integer);
                                }
                            }
                            else if (string.Equals(Sub, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    payload.Sub = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Sub, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Jti, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.String)
                                {
                                    payload.Jti = (string)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Jti, JsonToken.String);
                                }
                            }
                            else if (string.Equals(Nbf, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.Integer)
                                {
                                    payload.Nbf = (long)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Nbf, JsonToken.Integer);
                                }
                            }
                            else if (string.Equals(Iat, propertyName, StringComparison.Ordinal))
                            {
                                if (reader.Read() && reader.TokenType == JsonToken.Integer)
                                {
                                    payload.Iat = (long)reader.Value;
                                }
                                else if (reader.TokenType != JsonToken.Null)
                                {
                                    ThrowHelper.FormatMalformedJson(Claims.Iat, JsonToken.Integer);
                                }
                            }
                            else
                            {
                                name = (string)reader.Value;
                            }

                            break;

                        case JsonToken.String:
                        case JsonToken.Integer:
                        case JsonToken.Float:
                        case JsonToken.Boolean:
                            payload[name] = reader.Value;
                            break;

                        case JsonToken.Null:
                            payload[name] = null;
                            break;

                        case JsonToken.StartObject:
                            payload[name] = JToken.FromObject(JsonParser.ReadJson(reader));
                            break;
                        case JsonToken.StartArray:
                            var array = JsonParser.ReadJsonArray(reader);
                            payload[name] = array;
                            break;

                        case JsonToken.EndObject:
                            break;
                        default:
                            ThrowHelper.FormatMalformedJson();
                            break;
                    }
                }

                return payload;
            }
        }
    }
}
#endif
