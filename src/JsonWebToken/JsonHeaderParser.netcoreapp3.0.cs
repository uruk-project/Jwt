// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    public static partial class JsonHeaderParser
    {
        // Headers
        private static readonly byte[] Alg = { 97, 108, 103 };
        private static readonly byte[] Enc = { 101, 110, 99 };
        private static readonly byte[] Kid = { 107, 105, 100 };
        private static readonly byte[] Cty = { 99, 116, 121 };
        private static readonly byte[] Zip = { 122, 105, 112 };
        private static readonly byte[] Crit = { 99, 114, 105, 116 };
        
        private static JwtHeader ReadJsonHeader(ReadOnlySpan<byte> buffer)
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
                        ReadOnlySpan<byte> valueSpan = reader.ValueSpan;
                        ref byte refValueSpan = ref MemoryMarshal.GetReference(valueSpan);
                        if (valueSpan.Length == 3)
                        {
                            if (JsonParser.ThreeBytesEqual(ref refValueSpan, ref Alg[0], valueSpan.Length))
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
                            else if (JsonParser.ThreeBytesEqual(ref refValueSpan, ref Enc[0], valueSpan.Length))
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
                            else if (JsonParser.ThreeBytesEqual(ref refValueSpan, ref Kid[0], valueSpan.Length))
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
                            else if (JsonParser.ThreeBytesEqual(ref refValueSpan, ref Cty[0], valueSpan.Length))
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
                            else if (JsonParser.ThreeBytesEqual(ref refValueSpan, ref Zip[0], valueSpan.Length))
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
                        }                     
                        else if (valueSpan.Length == 4 && JsonParser.FourBytesEqual(ref refValueSpan, ref Crit[0], valueSpan.Length))
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