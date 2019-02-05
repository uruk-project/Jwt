// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static partial class JsonHeaderParser
    {
        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static unsafe JwtHeader ParseHeader(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                JwtThrowHelper.FormatNotJson();
            }

            JwtHeader header = new JwtHeader();
            string name = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        ReadOnlySpan<byte> propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
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
                                            header.Alg = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Alg, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7234915u /* 'enc' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Enc = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Enc, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 6908772u /* 'kid' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Kid = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Kid, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7627641u /* 'cty' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Cty = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Cty, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7959664u /* 'typ' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Typ = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Typ, JsonTokenType.String);
                                        }
                                    }
#if !NETSTANDARD
                                    else if (property == 7365995u /* 'epk' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                                        {
                                            header.Epk = ECJwk.FromJsonReader(ref reader);
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Epk, JsonTokenType.StartObject);
                                        }
                                    }
                                    else if (property == 7364981u /* 'apu' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Apu = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Apu, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7364982u /* 'apv' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Apv = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Apv, JsonTokenType.String);
                                        }
                                    }
#endif
                                    else if (property == 6912624u /* 'zip' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            header.Zip = reader.GetString();
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Zip, JsonTokenType.String);
                                        }
                                    }
                                    else
                                    {
                                        name = reader.GetString();
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
                                                crit.Add(reader.GetString());
                                            }

                                            if (reader.TokenType != JsonTokenType.EndArray)
                                            {
                                                JwtThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonTokenType.String);
                                            }

                                            header.Crit = crit;
                                        }
                                        else
                                        {
                                            JwtThrowHelper.FormatMalformedJson(HeaderParameters.Crit, JsonTokenType.StartObject);
                                        }
                                    }
                                    else
                                    {
                                        name = reader.GetString();
                                    }

                                    break;
                                default:
                                    name = reader.GetString();
                                    break;
                            }
                        }

                        break;

                    case JsonTokenType.String:
                        string stringValue = reader.GetString();
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
                        if (reader.TryGetInt64(out long longValue))
                        {
                            header[name] = longValue;
                        }
                        else
                        {
                            if (reader.TryGetDouble(out double doubleValue))
                            {
                                header[name] = doubleValue;
                            }
                            else
                            {
                                JwtThrowHelper.FormatNotSupportedNumber(name);
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
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return header;
        }
    }
}
