// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static class JwtPayloadParser
    {
        internal const uint Aud = 6583649u;
        internal const uint Iss = 7566185u;
        internal const uint Jti = 6911082u;
        internal const uint Sub = 6452595u;
        internal const uint Exp = 7370853u;
        internal const uint Iat = 7627113u;
        internal const uint Nbf = 6709870u;

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="policy"></param>
        public static JwtPayload ParsePayload(ReadOnlySpan<byte> buffer, TokenValidationPolicy policy)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            var payload = new JwtPayload();
            byte control = policy.Control;
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var name = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                reader.Read();
                var type = reader.TokenType;
                if (name.Length == 3)
                {
                    uint nameValue = IntegerMarshal.ReadUInt24(name);
                    switch (nameValue)
                    {
                        case Aud:
                            if (type == JsonTokenType.String)
                            {
                                if (policy.RequireAudience)
                                {
                                    var audiencesBinary = policy.RequiredAudiencesBinary;
                                    var audiences = policy.RequiredAudiences;
                                    for (int i = 0; i < audiencesBinary.Length; i++)
                                    {
                                        if (reader.ValueTextEquals(audiencesBinary[i]))
                                        {
                                            payload.Aud = new[] { audiences[i] };
                                            control &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                                            break;
                                        }
                                    }

                                    control &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                                }
                                else
                                {
                                    payload.Aud = new[] { reader.GetString()! };
                                }
                            }
                            else if (type == JsonTokenType.StartArray)
                            {
                                if (policy.RequireAudience)
                                {
                                    var audiences = new List<string>();
                                    while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                    {
                                        var requiredAudiences = policy.RequiredAudiencesBinary;
                                        for (int i = 0; i < requiredAudiences.Length; i++)
                                        {
                                            if (reader.ValueTextEquals(requiredAudiences[i]))
                                            {
                                                control &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                                                break;
                                            }
                                        }

                                        audiences.Add(reader.GetString()!);
                                        control &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                                    }

                                    if (reader.TokenType != JsonTokenType.EndArray)
                                    {
                                        ThrowHelper.ThrowFormatException_MalformedJson("The 'aud' claim must be an array of string or a string.");
                                    }

                                    payload.Aud = audiences.ToArray();
                                }
                                else
                                {
                                    payload.Aud = JsonParser.ReadStringArray(ref reader);
                                }
                            }
                            else
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The 'aud' claim must be an array of string or a string.");
                            }

                            continue;

                        case Iss:
                            if (policy.RequireIssuer)
                            {
                                if (reader.ValueTextEquals(policy.RequiredIssuerBinary))
                                {
                                    payload.Iss = policy.RequiredIssuer;
                                    control &= unchecked((byte)~TokenValidationPolicy.IssuerFlag);
                                }
                                else
                                {
                                    control &= unchecked((byte)~JwtPayload.MissingIssuerFlag);
                                }
                            }
                            else
                            {
                                payload.Iss = reader.GetString();
                            }

                            continue;

                        case Exp:
                            if (!reader.TryGetInt64(out long longValue))
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'exp' must be an integral number.");
                            }

                            if (policy.RequireExpirationTime)
                            {
                                control &= unchecked((byte)~JwtPayload.MissingExpirationFlag);
                            }

                            if (longValue >= EpochTime.UtcNow - policy.ClockSkew)
                            {
                                control &= unchecked((byte)~JwtPayload.ExpiredFlag);
                            }

                            payload.Exp = longValue;
                            continue;

                        case Iat:
                            if (!reader.TryGetInt64(out longValue))
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'iat' must be an integral number.");
                            }

                            payload.Iat = longValue;
                            continue;

                        case Nbf:
                            if (!reader.TryGetInt64(out longValue))
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'nbf' must be an integral number.");
                            }

                            // the 'nbf' claim is not common. The 2nd call to EpochTime.UtcNow should be rare.
                            if (longValue > EpochTime.UtcNow + policy.ClockSkew && (policy.Control & JwtPayload.ExpiredFlag) == JwtPayload.ExpiredFlag)
                            {
                                control |= JwtPayload.NotYetFlag;
                            }

                            payload.Nbf = longValue;
                            continue;

                        case Jti:
                            payload.Jti = reader.GetString();
                            continue;

                        case Sub:
                            payload.Sub = reader.GetString();
                            continue;
                    }
                }

                switch (type)
                {
                    case JsonTokenType.StartObject:
                        payload.Inner.Add(name, JsonParser.ReadJsonObject(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        payload.Inner.Add(name, JsonParser.ReadJsonArray(ref reader));
                        break;
                    case JsonTokenType.String:
                        payload.Inner.Add(name, reader.GetString()!);
                        break;
                    case JsonTokenType.True:
                        payload.Inner.Add(name, true);
                        break;
                    case JsonTokenType.False:
                        payload.Inner.Add(name, false);
                        break;
                    case JsonTokenType.Null:
                        payload.Inner.Add(name);
                        break;
                    case JsonTokenType.Number:
                        long longValue;

                        if (reader.TryGetInt64(out longValue))
                        {
                            payload.Inner.Add(name, longValue);
                        }
                        else
                        {
                            payload.Inner.Add(name, reader.GetDouble());
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

            payload.ValidationControl = control;

            return payload;
        }
    }
}
