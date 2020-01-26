// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static partial class JwtPayloadParser
    {
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

            var current = new JwtObject();
            var payload = new JwtPayload(current);
            byte control = policy.ValidationControl;
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var name = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                reader.Read();
                var type = reader.TokenType;
                switch (type)
                {
                    case JsonTokenType.StartObject:
                        current.Add(name, JsonParser.ReadJsonObject(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        if (name.Length == 3 && ReadThreeBytesAsInt32(name) == 6583649u /* aud */)
                        {
                            if (policy.RequireAudience)
                            {
                                var audiences = new List<JwtValue>();
                                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                {
                                    var requiredAudiences = policy.RequiredAudiences;
                                    for (int i = 0; i < requiredAudiences.Length; i++)
                                    {
                                        if (reader.ValueTextEquals(requiredAudiences[i]))
                                        {
                                            control &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                                            break;
                                        }
                                    }

                                    audiences.Add(new JwtValue(reader.GetString()));
                                    control &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                                }

                                if (reader.TokenType != JsonTokenType.EndArray)
                                {
                                    ThrowHelper.ThrowFormatException_MalformedJson("The 'aud' claim must be an array of string or a string.");
                                }

                                current.Add(new JwtProperty(Claims.AudUtf8, new JwtArray(audiences)));

                            }
                            else
                            {
                                // TODO : Well know property 'aud'
                                current.Add(name, JsonParser.ReadJsonArray(ref reader));
                            }
                        }
                        else
                        {
                            current.Add(name, JsonParser.ReadJsonArray(ref reader));
                        }

                        break;
                    case JsonTokenType.String:
                        if (name.Length == 3)
                        {
                            var refName = ReadThreeBytesAsInt32(name);
                            switch (refName)
                            {
                                /* iss */
                                case 7566185u:
                                    if (policy.RequireIssuer)
                                    {
                                        if (reader.ValueTextEquals(policy.RequiredIssuer))
                                        {
                                            current.Add(new JwtProperty(WellKnownProperty.Iss, policy.RequiredIssuerString!));
                                            control &= unchecked((byte)~TokenValidationPolicy.IssuerFlag);
                                        }
                                        else
                                        {
                                            control &= unchecked((byte)~JwtPayload.MissingIssuerFlag);
                                        }
                                    }
                                    else
                                    {
                                        // TODO : Fix when the Utf8JsonReader will allow
                                        // to read an unescaped string without allocating a string
                                        current.Add(new JwtProperty(WellKnownProperty.Iss, reader.GetString()));
                                    }

                                    continue;

                                /* aud */
                                case 6583649u:
                                    if (policy.RequireAudience)
                                    {
                                        var audiences = policy.RequiredAudiences;
                                        for (int i = 0; i < audiences.Length; i++)
                                        {
                                            if (reader.ValueTextEquals(audiences[i]))
                                            {
                                                current.Add(new JwtProperty(WellKnownProperty.Aud, audiences[i]));
                                                control &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                                                break;
                                            }
                                        }

                                        control &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                                    }
                                    else
                                    {
                                        // TODO : Fix when the Utf8JsonReader will allow
                                        // to read an unescaped string without allocating a string
                                        JwtProperty property = new JwtProperty(WellKnownProperty.Aud, reader.GetString());
                                        current.Add(property);
                                    }

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
                            var refName = ReadThreeBytesAsInt32(name);
                            switch (refName)
                            {
                                /* exp */
                                case 7370853u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        if (policy.RequireExpirationTime)
                                        {
                                            control &= unchecked((byte)~JwtPayload.MissingExpirationFlag);
                                        }

                                        if (longValue >= EpochTime.UtcNow - policy.ClockSkrew)
                                        {
                                            control &= unchecked((byte)~JwtPayload.ExpiredFlag);
                                        }

                                        current.Add(new JwtProperty(WellKnownProperty.Exp, longValue));
                                        continue;
                                    }
                                    else
                                    {
                                        ThrowHelper.ThrowFormatException_MalformedJson("The claim 'exp' must be an integral number.");
                                    }
                                    break;

                                /* iat */
                                case 7627113u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        current.Add(new JwtProperty(WellKnownProperty.Iat, longValue));
                                        continue;
                                    }
                                    else
                                    {
                                        ThrowHelper.ThrowFormatException_MalformedJson("The claim 'iat' must be an integral number.");
                                    }
                                    break;

                                /* nbf */
                                case 6709870u:
                                    if (reader.TryGetInt64(out longValue))
                                    {
                                        // the 'nbf' claim is not common. The 2nd call to EpochTime.UtcNow should be rare.
                                        if (longValue <= EpochTime.UtcNow + policy.ClockSkrew)
                                        {
                                            control &= unchecked((byte)~JwtPayload.NotYetFlag);
                                        }

                                        current.Add(new JwtProperty(WellKnownProperty.Nbf, longValue));
                                        continue;
                                    }
                                    else
                                    {
                                        ThrowHelper.ThrowFormatException_MalformedJson("The claim 'nbf' must be an integral number.");
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

            payload.ValidationControl = control;

            return payload;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ReadThreeBytesAsInt32(ReadOnlySpan<byte> name)
        {
            return Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffffu;
        }
    }
}
