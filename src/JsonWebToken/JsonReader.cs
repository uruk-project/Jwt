// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System.Text.Json;
#else
using Newtonsoft.Json;
using System.Text;
#endif
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Newtonsoft.Json.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting Base64Url JSON data into a <see cref="Dictionary{TKey, TValue}"/>
    /// </summary>
    public static class JsonParser
    {
        /// <summary>
        /// Parses the <paramref name="buffer"/> as JSON.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static Dictionary<string, object> Parse(ReadOnlySpan<byte> buffer)
        {
            return ReadJson(buffer);
        }

        public static JwtHeader ParseHeader(ReadOnlySpan<byte> buffer)
        {
            return ReadJsonHeader(buffer);
        }

        public static JwtPayload ParsePayload(ReadOnlySpan<byte> buffer)
        {
            return ReadJsonPayload(buffer);
        }

#if NETCOREAPP3_0
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
                throw new FormatException("Expect '{'.");
            }

            JwtHeader header = new JwtHeader();
            string name = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        if (reader.ValueSpan.SequenceEqual(Alg))
                        {
                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                header.Alg = reader.GetStringValue();
                            }
                            else if (reader.TokenType != JsonTokenType.Null)
                            {
                                throw new FormatException();
                            }
                        }
                        else if (reader.ValueSpan.SequenceEqual(Enc))
                        {
                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                header.Enc = reader.GetStringValue();
                            }
                            else if (reader.TokenType != JsonTokenType.Null)
                            {
                                throw new FormatException();
                            }
                        }
                        else if (reader.ValueSpan.SequenceEqual(Kid))
                        {
                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                header.Kid = reader.GetStringValue();
                            }
                            else if (reader.TokenType != JsonTokenType.Null)
                            {
                                throw new FormatException();
                            }
                        }
                        else if (reader.ValueSpan.SequenceEqual(Cty))
                        {
                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                header.Cty = reader.GetStringValue();
                            }
                            else if (reader.TokenType != JsonTokenType.Null)
                            {
                                throw new FormatException();
                            }
                        }
                        else if (reader.ValueSpan.SequenceEqual(Zip))
                        {
                            if (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                header.Zip = reader.GetStringValue();
                            }
                            else if (reader.TokenType != JsonTokenType.Null)
                            {
                                throw new FormatException();
                            }
                        }
                        else if (reader.ValueSpan.SequenceEqual(Crit))
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
                                    throw new FormatException("The 'crit' header parameter must contain string only.");
                                }

                                header.Crit = crit;
                            }
                            else
                            {
                                throw new FormatException();
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
                                throw new FormatException();
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
                        throw new FormatException();
                }
            }

            return header;
        }


        private static readonly byte[] Exp = { 101, 120, 112 };
        private static readonly byte[] Jti = { 106, 116, 105 };
        private static readonly byte[] Nbf = { 110, 98, 102 };
        private static readonly byte[] Iss = { 105, 115, 115 };
        private static readonly byte[] Iat = { 105, 97, 116 };
        private static readonly byte[] Aud = { 97, 117, 100 };
        private static readonly byte[] Sub = { 115, 117, 98 };

        private static JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
        {

            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new FormatException("Expect a JSON object.");
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
                                throw new FormatException();
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
                                    var aud = new List<string>();
                                    while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        aud.Add(reader.GetStringValue());
                                    }

                                    if (reader.TokenType != JsonTokenType.EndArray)
                                    {
                                        throw new FormatException("The 'aud' claim must contain string only.");
                                    }

                                    payload.Aud = aud;
                                }
                                else if (reader.TokenType != JsonTokenType.Null)
                                {
                                    throw new FormatException();
                                }
                            }
                            else
                            {
                                throw new FormatException();
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
                                throw new FormatException();
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
                                throw new FormatException();
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
                                throw new FormatException();
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
                                throw new FormatException();
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
                                throw new FormatException();
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
                                throw new FormatException();
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
                        throw new FormatException();
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
                                var newObj = new Dictionary<string, object>();
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
                                        throw new FormatException();
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = ReadJsonArray(ref reader);
                                current.Add(name, array);
                                break;
                            default:
                                throw new FormatException();
                        }
                        break;
                    case JsonTokenType.StartObject:
                        break;
                    default:
                        throw new FormatException();
                }
            }

            return stack.Peek();
        }

        private static List<object> ReadJsonArray(ref Utf8JsonReader reader)
        {
            List<object> array = new List<object>();
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
                                throw new FormatException();
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
                    case JsonTokenType.StartArray:
                        var innerArray = ReadJsonArray(ref reader);
                        array.Add(innerArray);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.PropertyName:
                    case JsonTokenType.StartObject:
                    default:
                        break;
                }
            }

            return array;
        }

#else
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Dictionary<string, object> ReadJson(ReadOnlySpan<byte> buffer)
        {
#if !NETSTANDARD2_0
                var json = Encoding.UTF8.GetString(buffer);
#else
            var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
        }

        public static JwtHeader ReadJsonHeader(ReadOnlySpan<byte> buffer)
        {
            return new JwtHeader(ReadJson(buffer));
        }

        public static JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
        {
            return new JwtPayload(ReadJson(buffer));
        }
#endif
    }
}
