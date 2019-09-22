// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        public static JwtPayload ParsePayload(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            var current = new JwtObject();
            var payload = new JwtPayload(current);
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
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
                            var refName = Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffffu;
                            switch (refName)
                            {
                                /* iss */
                                case 7566185u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Iss, reader.GetString()));
                                    continue;

                                /* aud */
                                case 6583649u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Aud, reader.GetString()));
                                    continue;

                                /* jti */
                                case 6911082u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Jti, reader.GetString()));
                                    continue;

                                /* sub */
                                case 6452595u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Sub, reader.GetString()));
                                    continue;
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
                        long longValue;
                        if (name.Length == 3)
                        {
                            var refName = Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffffu;
                            switch (refName)
                            {
                                /* exp */
                                case 7370853u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        current.Add(new JwtProperty(WellKnownProperty.Exp, longValue));
                                        continue;
                                    }
                                    break;

                                /* iat */
                                case 7627113u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        current.Add(new JwtProperty(WellKnownProperty.Iat, longValue));
                                        continue;
                                    }
                                    break;

                                /* nbf */
                                case 6709870u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        current.Add(new JwtProperty(WellKnownProperty.Nbf, longValue));
                                        continue;
                                    }
                                    break;
                            }
                        }

                        if (reader.TryGetInt64(out longValue))
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
                                ThrowHelper.ThrowFormatException_NotSupportedNumberValue(name);
                            }
                        }
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            return payload;
        }
    }
}
