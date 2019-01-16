// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    public static partial class JsonPayloadParser
    {
        private static unsafe JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.FormatNotJson();
            }

            JwtPayload payload = new JwtPayload();
            string name = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        var propertyName = reader.ValueSpan;
                        fixed (byte* pPropertyByte = propertyName)
                        {
                            switch (propertyName.Length)
                            {
                                case 3:
                                    uint property = (uint)(((*(ushort*)pPropertyByte) << 8) | *(pPropertyByte + 2));
                                    
                                    if (property == 7563635u /* 'iss' */) 
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            payload.Iss = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Iss, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7692644u /* 'aud' */)
                                    {
                                        if (reader.Read())
                                        {
                                            if (reader.TokenType == JsonTokenType.String)
                                            {
                                                payload.Aud = new List<string> { reader.GetStringValue() };
                                            }
                                            else if (reader.TokenType == JsonTokenType.StartArray)
                                            {
                                                var aud = new List<string>(2);
                                                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                                {
                                                    aud.Add(reader.GetStringValue());
                                                }

                                                if (reader.TokenType != JsonTokenType.EndArray)
                                                {
                                                    ThrowHelper.FormatMalformedJson(Claims.Aud, JsonTokenType.String);
                                                }

                                                payload.Aud = aud;
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                ThrowHelper.FormatMalformedJson(Claims.Aud, JsonTokenType.String);
                                            }
                                        }
                                        else
                                        {
                                            ThrowHelper.FormatMalformedJson();
                                        }
                                    }
                                    else if (property == 7890288 /* 'exp' */)
                                    {
                                        if (reader.Read() && reader.TryGetInt64Value(out long expValue))
                                        {
                                            payload.Exp = expValue;
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Exp, JsonTokenType.Number);
                                        }
                                    }
                                    else if (property == 7697250u /* 'sub' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            payload.Sub = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Sub, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7629417 /* 'jti' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            payload.Jti = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Jti, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 6450790u /* 'nbf' */)
                                    {
                                        if (reader.Read() && reader.TryGetInt64Value(out long nbfValue))
                                        {
                                            payload.Nbf = nbfValue;
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Nbf, JsonTokenType.Number);
                                        }
                                    }
                                    // 'iat' = { 105, 97, 116 };
                                    else if (property == 6383988u)
                                    {
                                        if (reader.Read() && reader.TryGetInt64Value(out long iatValue))
                                        {
                                            payload.Iat = iatValue;
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(Claims.Iat, JsonTokenType.Number);
                                        }
                                    }
                                    else
                                    {
                                        name = reader.GetStringValue();
                                    }

                                    break;
                                default:
                                    name = reader.GetStringValue();
                                    break;
                            }
                        }
                        break;

                    case JsonTokenType.String:
                        payload[name] = reader.GetStringValue();
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
                        if (reader.TryGetInt64Value(out long longValue))
                        {
                            payload[name] = longValue;
                        }
                        else
                        {
                            if (reader.TryGetDoubleValue(out double doubleValue))
                            {
                                payload[name] = doubleValue;
                            }
                            else
                            {
                                ThrowHelper.FormatNotSupportedNumber(name);
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
                        ThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return payload;
        }
    }
}
#endif