// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static partial class JsonPayloadParser
    {
        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static unsafe JwtPayload ParsePayload(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                JwtThrowHelper.FormatNotJson();
            }

            JwtPayload payload = new JwtPayload();
            string name = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        fixed (byte* pPropertyByte = propertyName)
                        {
                            switch (propertyName.Length)
                            {
                                case 3:
                                    short propertyShort = *(short*)(pPropertyByte + 1);
                                    switch (*pPropertyByte)
                                    {
                                        case (byte)'i' when propertyShort == 29555 /* 'iss' */:
                                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                            {
                                                payload.Iss = reader.GetString();
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Iss, JsonTokenType.String);
                                            }
                                            break;
                                        case (byte)'a' when propertyShort == 25717 /* 'aud' */:
                                            if (reader.Read())
                                            {
                                                if (reader.TokenType == JsonTokenType.String)
                                                {
                                                    payload.Aud = new List<string> { reader.GetString() };
                                                }
                                                else if (reader.TokenType == JsonTokenType.StartArray)
                                                {
                                                    var aud = new List<string>(2);
                                                    while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                                    {
                                                        aud.Add(reader.GetString());
                                                    }

                                                    if (reader.TokenType != JsonTokenType.EndArray)
                                                    {
                                                        JwtThrowHelper.FormatMalformedJson(Claims.Aud, JsonTokenType.String);
                                                    }

                                                    payload.Aud = aud;
                                                }
                                                else if (reader.TokenType != JsonTokenType.Null)
                                                {
                                                    JwtThrowHelper.FormatMalformedJson(Claims.Aud, JsonTokenType.String);
                                                }
                                            }
                                            else
                                            {
                                                JwtThrowHelper.FormatMalformedJson();
                                            }
                                            break;
                                        case (byte)'e' when propertyShort == 28792 /* 'exp' */:
                                            if (reader.Read() && reader.TryGetInt64(out long expValue))
                                            {
                                                payload.Exp = expValue;
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Exp, JsonTokenType.Number);
                                            }
                                            break;
                                        case (byte)'s' when propertyShort == 25205 /* 'sub' */:
                                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                            {
                                                payload.Sub = reader.GetString();
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Sub, JsonTokenType.String);
                                            }
                                            break;
                                        case (byte)'j' when propertyShort == 26996 /* 'jti' */:
                                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                            {
                                                payload.Jti = reader.GetString();
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Jti, JsonTokenType.String);
                                            }
                                            break;
                                        case (byte)'n' when propertyShort == 26210 /* 'nbf' */:
                                            if (reader.Read() && reader.TryGetInt64(out long nbfValue))
                                            {
                                                payload.Nbf = nbfValue;
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Nbf, JsonTokenType.Number);
                                            }
                                            break;
                                        case (byte)'i' when propertyShort == 29793 /* 'iat' */:
                                            if (reader.Read() && reader.TryGetInt64(out long iatValue))
                                            {
                                                payload.Iat = iatValue;
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(Claims.Iat, JsonTokenType.Number);
                                            }
                                            break;
                                        default:
                                            name = reader.GetString();
                                            break;
                                    }
                                    break;
                                default:
                                    name = reader.GetString();
                                    break;
                            }
                        }
                        break;

                    case JsonTokenType.String:
                        payload[name] = reader.GetString();
                        break;
                    case JsonTokenType.True:
                        payload[name] = true;
                        break;
                    case JsonTokenType.False:
                        payload[name] = false;
                        break;
                    case JsonTokenType.Null:
                        payload[name] = null;
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64(out long longValue))
                        {
                            payload[name] = longValue;
                        }
                        else
                        {
                            if (reader.TryGetDouble(out double doubleValue))
                            {
                                payload[name] = doubleValue;
                            }
                            else
                            {
                                JwtThrowHelper.FormatNotSupportedNumber(name);
                            }
                        }
                        break;

                    case JsonTokenType.StartObject:
                        payload[name] = JToken.FromObject(JsonParser.ReadJson(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        var array = JsonParser.ReadJsonArray(ref reader);
                        payload[name] = array;
                        break;

                    case JsonTokenType.EndObject:
                        break;
                    default:
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return payload;
        }
    }
}
