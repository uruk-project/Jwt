// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Text;
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
            return new JwtHeader(ReadHeader(buffer));
        }

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        internal static unsafe JwtObject ReadHeader(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                JwtThrowHelper.FormatMalformedJson();
            }

            return ReadJwtHeader(ref reader);
        }

        internal unsafe static JwtObject ReadJwtHeader(ref Utf8JsonReader reader)
        {
            var current = new JwtObject();
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return current;
                    case JsonTokenType.PropertyName:
                        var name = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        reader.Read();
                        var type = reader.TokenType;
                        switch (type)
                        {
                            case JsonTokenType.StartObject:
                                current.Add(name, JsonParser.ReadJsonObject(ref reader));
                                break;
                            case JsonTokenType.StartArray:
                                current.Add(name, JsonParser.ReadJsonArray(ref reader));
                                break;
                            case JsonTokenType.String:
                                if (name.Length == 3)
                                {
                                    fixed (byte* pName = name)
                                    {
                                        short nameSuffix = *(short*)(pName + 1);
                                        switch (*pName)
                                        {
                                            case (byte)'a' when nameSuffix == 26476 /* alg */:
                                            case (byte)'e' when nameSuffix == 25454 /* enc */:
                                            case (byte)'z' when nameSuffix == 28777 /* zip */:
                                                // TODO : Fix when the Utf8JsonReader will allow
                                                // to read an unescaped string without allocating a string
                                                current.Add(new JwtProperty(name, Encoding.UTF8.GetBytes(reader.GetString())));
                                                continue;
                                        }
                                    }
                                }
                                current.Add(name, reader.GetString());
                                break;
                            case JsonTokenType.True:
                                current.Add(name, true);
                                break;
                            case JsonTokenType.False:
                                current.Add(name, false);
                                break;
                            case JsonTokenType.Null:
                                current.Add(name);
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64(out long longValue))
                                {
                                    current.Add(name, longValue);
                                }
                                else
                                {
                                    if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        current.Add(name, doubleValue);
                                    }
                                    else
                                    {
                                        JwtThrowHelper.FormatNotSupportedNumber(name);
                                    }
                                }
                                break;
                            default:
                                JwtThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    default:
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            JwtThrowHelper.FormatMalformedJson();
            return null;
        }
    }
}
