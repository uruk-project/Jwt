// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
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
            return ReadPayload(buffer);
        }

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="buffer"></param>
        internal static unsafe JwtPayload ReadPayload(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            return ReadJwtPayload(ref reader);
        }

        internal unsafe static JwtPayload ReadJwtPayload(ref Utf8JsonReader reader)
        {
            var current = new JwtObject(3);
            var payload = new JwtPayload(current);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return payload;
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
                                            case (byte)'i' when nameSuffix == 29555 /* iss */:
                                                // TODO : Fix when the Utf8JsonReader will allow
                                                // to read an unescaped string without allocating a string
                                                current.Add(new JwtProperty(WellKnownProperty.Iss, reader.GetString()));
                                                continue;

                                            case (byte)'a' when nameSuffix == 25717 /* aud */:
                                                // TODO : Fix when the Utf8JsonReader will allow
                                                // to read an unescaped string without allocating a string
                                                current.Add(new JwtProperty(WellKnownProperty.Aud, reader.GetString()));
                                                continue;

                                            case (byte)'j' when nameSuffix == 26996 /* jti */:
                                                // TODO : Fix when the Utf8JsonReader will allow
                                                // to read an unescaped string without allocating a string
                                                current.Add(new JwtProperty(WellKnownProperty.Jti, reader.GetString()));
                                                continue;

                                            case (byte)'s' when nameSuffix == 25205 /* sub */:
                                                // TODO : Fix when the Utf8JsonReader will allow
                                                // to read an unescaped string without allocating a string
                                                current.Add(new JwtProperty(WellKnownProperty.Sub, reader.GetString()));
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
                                long longValue;
                                if (name.Length == 3)
                                {
                                    fixed (byte* pName = name)
                                    {
                                        short nameSuffix = *(short*)(pName + 1);
                                        switch (*pName)
                                        {
                                            case (byte)'e' when nameSuffix == 28792 /* exp */:
                                                if (reader.TryGetInt64(out longValue))
                                                {
                                                    current.Add(new JwtProperty(WellKnownProperty.Exp, longValue));
                                                    continue;
                                                }

                                                break;
                                            case (byte)'i' when nameSuffix == 29793 /* iat */:
                                                if (reader.TryGetInt64(out longValue))
                                                {
                                                    current.Add(new JwtProperty(WellKnownProperty.Iat, longValue));
                                                    continue;
                                                }

                                                break;
                                            case (byte)'n' when nameSuffix == 26210 /* nbf */:
                                                if (reader.TryGetInt64(out longValue))
                                                {
                                                    current.Add(new JwtProperty(WellKnownProperty.Nbf, longValue));
                                                    continue;
                                                }

                                                break;
                                        }
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
                        break;
                    default:
                        ThrowHelper.ThrowFormatException_MalformedJson();
                        break;
                }
            }

            ThrowHelper.ThrowFormatException_MalformedJson();
            return null;
        }
    }
}
