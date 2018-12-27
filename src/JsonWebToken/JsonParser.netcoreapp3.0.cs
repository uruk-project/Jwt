// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System.Text.Json;
using System.Collections.Generic;
using JsonWebToken.Internal;
using System;
using Newtonsoft.Json.Linq;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting Base64Url JSON data into a <see cref="Dictionary{TKey, TValue}"/>
    /// </summary>
    public static partial class JsonParser
    {
        // Headers
        private static readonly byte[] Alg = { 97, 108, 103 };
        private static readonly byte[] Enc = { 101, 110, 99 };
        private static readonly byte[] Kid = { 107, 105, 100 };
        private static readonly byte[] Cty = { 99, 116, 121 };
        private static readonly byte[] Zip = { 122, 105, 112 };
        private static readonly byte[] Crit = { 99, 114, 105, 116 };

        // claims
        private static readonly byte[] Exp = { 101, 120, 112 };
        private static readonly byte[] Jti = { 106, 116, 105 };
        private static readonly byte[] Nbf = { 110, 98, 102 };
        private static readonly byte[] Iss = { 105, 115, 115 };
        private static readonly byte[] Iat = { 105, 97, 116 };
        private static readonly byte[] Aud = { 97, 117, 100 };
        private static readonly byte[] Sub = { 115, 117, 98 };

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
                        if (valueSpan.SequenceEqual(Alg))
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
                        else if (valueSpan.SequenceEqual(Enc))
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
                        else if (valueSpan.SequenceEqual(Kid))
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
                        else if (valueSpan.SequenceEqual(Cty))
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
                        else if (valueSpan.SequenceEqual(Zip))
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
                        else if (valueSpan.SequenceEqual(Crit))
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
                        header[name] = ReadJson(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        var array = ReadJsonArray(ref reader);
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

        private static JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
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
                        if (reader.ValueSpan.SequenceEqual(Iss))
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
                        else if (reader.ValueSpan.SequenceEqual(Aud))
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
                        else if (reader.ValueSpan.SequenceEqual(Exp))
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
                        else if (reader.ValueSpan.SequenceEqual(Sub))
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
                        else if (reader.ValueSpan.SequenceEqual(Jti))
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
                        else if (reader.ValueSpan.SequenceEqual(Nbf))
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
                        else if (reader.ValueSpan.SequenceEqual(Iat))
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

                    case JsonTokenType.String:
                        string stringValue = reader.GetStringValue();
                        payload[name] = stringValue;
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
                        payload[name] = JToken.FromObject(ReadJson(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        var array = ReadJsonArray(ref reader);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Dictionary<string, object> ReadJson(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            return ReadJson(ref reader);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Dictionary<string, object> ReadJson(ref Utf8JsonReader reader)
        {
            Stack<Dictionary<string, object>> stack = new Stack<Dictionary<string, object>>();
            stack.Push(new Dictionary<string, object>());
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        if (stack.Count != 1)
                        {
                            stack.Pop();
                            break;
                        }
                        else
                        {
                            return stack.Peek();
                        }
                    case JsonTokenType.PropertyName:
                        string name = reader.GetStringValue();
                        reader.Read();
                        var type = reader.TokenType;
                        var current = stack.Peek();
                        switch (type)
                        {
                            case JsonTokenType.String:
                                current[name] = reader.GetStringValue();
                                break;
                            case JsonTokenType.StartObject:
                                var newObj = new Dictionary<string, object>(2);
                                current[name] = newObj;
                                stack.Push(newObj);
                                break;
                            case JsonTokenType.True:
                                current[name] = true;
                                break;
                            case JsonTokenType.False:
                                current[name] = false;
                                break;
                            case JsonTokenType.Null:
                                current[name] = null;
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64Value(out long longValue))
                                {
                                    current[name] = longValue;
                                }
                                else
                                {
                                    if (reader.TryGetDoubleValue(out double doubleValue))
                                    {
                                        current[name] = doubleValue;
                                    }
                                    else
                                    {
                                        ThrowHelper.FormatNotSupportedNumber(name);
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = ReadJsonArray(ref reader);
                                current.Add(name, array);
                                break;
                            default:
                                ThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    case JsonTokenType.StartObject:
                        break;
                    default:
                        ThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return stack.Peek();
        }

        private static List<object> ReadJsonArray(ref Utf8JsonReader reader)
        {
            List<object> array = new List<object>(2);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndArray:
                        return array;
                    case JsonTokenType.Null:
                        array.Add(null);
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64Value(out long longValue))
                        {
                            array.Add(longValue);
                        }
                        else
                        {
                            if (reader.TryGetDoubleValue(out double doubleValue))
                            {
                                array.Add(doubleValue);
                            }
                            else
                            {
                                ThrowHelper.FormatMalformedJson();
                            }
                        }

                        break;
                    case JsonTokenType.String:
                        string valueString = reader.GetStringValue();
                        array.Add(valueString);
                        break;
                    case JsonTokenType.True:
                        array.Add(true);
                        break;
                    case JsonTokenType.False:
                        array.Add(false);
                        break;
                    case JsonTokenType.StartObject:
                        array.Add(ReadJson(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        var innerArray = ReadJsonArray(ref reader);
                        array.Add(innerArray);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.PropertyName:
                    default:
                        break;
                }
            }

            return array;
        }
    }
}
#endif