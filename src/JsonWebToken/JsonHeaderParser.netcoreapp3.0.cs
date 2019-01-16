﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    public static unsafe partial class JsonHeaderParser
    {
        private static unsafe JwtHeader ReadJsonHeader(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.FormatNotJson();
            }

            JwtHeader header = new JwtHeader();
            string name = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        ReadOnlySpan<byte> propertyName = reader.ValueSpan;
                        fixed (byte* pPropertyByte = propertyName)
                        {
                            switch (propertyName.Length)
                            {
                                case 3:
                                    uint property = (uint)(((*(ushort*)pPropertyByte) << 8) | *(pPropertyByte + 2));
                                    
                                    if (property == 7102823u /* 'alg' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Alg = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Alg, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7234915u /* 'enc' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Enc = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Enc, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 6908772u /* 'kid' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Kid = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Kid, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7627641u /* 'cty' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Cty = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Cty, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7959664u /* 'typ' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Typ = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Typ, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7365995u /* 'epk' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                                        {
                                            header.Epk = ECJwk.FromJsonReader(ref reader);
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Epk, JsonTokenType.StartObject);
                                        }
                                    }
                                    else if (property == 7364981u /* 'apu' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Apu = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Apu, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7364982u /* 'apv' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Apv = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Apv, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 6912624u /* 'zip' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Zip = reader.GetStringValue();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Zip, JsonTokenType.String);
                                        }
                                    }
                                    else
                                    {
                                        name = reader.GetStringValue();
                                    }
                                    break;
                                case 4:
                                    property = *(uint*)pPropertyByte;
                                    if (property == 1953067619u /* 'crit' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.StartArray)
                                        {
                                            var crit = new List<string>();
                                            while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                            {
                                                crit.Add(reader.GetStringValue());
                                            }

                                            if (reader.TokenType != JsonTokenType.EndArray)
                                            {
                                                ThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonTokenType.String);
                                            }

                                            header.Crit = crit;
                                        }
                                        else
                                        {
                                            ThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonTokenType.StartObject);
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
                        string stringValue = reader.GetStringValue();
                        header[name] = stringValue;
                        break;
                    case JsonTokenType.True:
                        header[name] = true;
                        break;
                    case JsonTokenType.False:
                        header[name] = false;
                        break;
                    case JsonTokenType.Null:
                        header[name] = null;
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64Value(out long longValue))
                        {
                            header[name] = longValue;
                        }
                        else
                        {
                            if (reader.TryGetDoubleValue(out double doubleValue))
                            {
                                header[name] = doubleValue;
                            }
                            else
                            {
                                ThrowHelper.FormatNotSupportedNumber(name);
                            }
                        }
                        break;

                    case JsonTokenType.StartObject:
                        header[name] = JsonParser.ReadJson(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        var array = JsonParser.ReadJsonArray(ref reader);
                        header[name] = array;
                        break;

                    case JsonTokenType.EndObject:
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
#endif