// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    [Obsolete]
    public static class JwtHeaderParser
    {
        internal const uint Alg = 6777953u;
        internal const uint Enc = 6516325u;
        internal const uint Zip = 7367034u;
        internal const uint Cty = 7959651u;
        internal const uint Typ = 7371124u;
        internal const uint Kid = 6580587u;
        internal const uint Crit = 1953067619u;

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="policy"></param>
        public static JwtHeader ParseHeader(ReadOnlySpan<byte> buffer, TokenValidationPolicy policy)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            var header = new JwtHeader();
            while (reader.Read())
            {
                if (!(reader.TokenType is JsonTokenType.PropertyName))
                {
                    break;
                }

                var name = reader.ValueSpan;
                reader.Read();
                var type = reader.TokenType;


                if (name.Length == 3)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var refName = IntegerMarshal.ReadUInt24(name);
                        switch (refName)
                        {
                            case Alg:
                                var alg = reader.ValueSpan;
                                if (SignatureAlgorithm.TryParse(alg, out var signatureAlgorithm))
                                {
                                    header.SignatureAlgorithm = signatureAlgorithm;
                                }
                                else if (KeyManagementAlgorithm.TryParse(alg, out var keyManagementAlgorithm))
                                {
                                    header.KeyManagementAlgorithm = keyManagementAlgorithm;
                                }
                                else if (SignatureAlgorithm.TryParseSlow(ref reader, out signatureAlgorithm))
                                {
                                    header.SignatureAlgorithm = signatureAlgorithm;
                                }
                                else if (KeyManagementAlgorithm.TryParseSlow(ref reader, out keyManagementAlgorithm))
                                {
                                    header.KeyManagementAlgorithm = keyManagementAlgorithm;
                                }
                                else
                                {
                                    header.SignatureAlgorithm = SignatureAlgorithm.Create(reader.GetString()!);
                                }

                                continue;

                            case Enc:
                                var enc = reader.ValueSpan;
                                if (EncryptionAlgorithm.TryParse(enc, out var encryptionAlgorithm))
                                {
                                    header.EncryptionAlgorithm = encryptionAlgorithm;
                                }
                                else if (EncryptionAlgorithm.TryParseSlow(ref reader, out encryptionAlgorithm))
                                {
                                    header.EncryptionAlgorithm = encryptionAlgorithm;
                                }
                                else
                                {
                                    header.EncryptionAlgorithm = EncryptionAlgorithm.Create(reader.GetString()!);
                                }

                                continue;

                            case Zip:
                                var zip = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                                if (CompressionAlgorithm.TryParse(zip, out var compressionAlgorithm))
                                {
                                    header.CompressionAlgorithm = compressionAlgorithm;
                                }
                                else if (CompressionAlgorithm.TryParseSlow(ref reader, out compressionAlgorithm))
                                {
                                    header.CompressionAlgorithm = compressionAlgorithm;
                                }
                                else
                                {
                                    header.CompressionAlgorithm = CompressionAlgorithm.Create(reader.GetString()!);
                                }

                                continue;

                            case Cty:
                                header.Cty = reader.GetString();
                                continue;

                            case Typ:
                                header.Typ = reader.GetString();
                                continue;

                            case Kid:
                                header.Kid = reader.GetString();
                                continue;
                        }
                    }
                }
                else if (name.Length == 4)
                {
                    if (reader.TokenType == JsonTokenType.StartArray && IntegerMarshal.ReadUInt32(name) == Crit)
                    {
                        var handlers = policy.CriticalHandlers;
                        if (handlers.Count != 0)
                        {
                            var criticalHeaderHandlers = new List<KeyValuePair<string, ICriticalHeaderHandler>>(handlers.Count);
                            var criticals = new List<JwtValue>();
                            while (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                string criticalHeader = reader.GetString()!;
                                criticals.Add(new JwtValue(criticalHeader));
                                if (handlers.TryGetValue(criticalHeader, out var handler))
                                {
                                    criticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, handler));
                                }
                                else
                                {
                                    criticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, null!));
                                }
                            }

                            header.CriticalHeaderHandlers = criticalHeaderHandlers;

                            if (reader.TokenType != JsonTokenType.EndArray)
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The 'crit' header parameter must be an array of string.");
                            }

                            header.Inner.Add(name, new JwtArray(criticals));
                        }
                        else
                        {
                            var criticals = new List<JwtValue>();
                            while (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                string criticalHeader = reader.GetString()!;
                                criticals.Add(new JwtValue(criticalHeader));
                            }

                            if (reader.TokenType != JsonTokenType.EndArray)
                            {
                                ThrowHelper.ThrowFormatException_MalformedJson("The 'crit' header parameter must be an array of string.");
                            }

                            header.Inner.Add(name, new JwtArray(criticals));
                        }

                        continue;
                    }
                }


                switch (type)
                {
                    case JsonTokenType.StartObject:
                        header.Inner.Add(name, JsonParser.ReadJsonObject(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        header.Inner.Add(name, JsonParser.ReadJsonArray(ref reader));
                        break;
                    case JsonTokenType.String:
                        header.Inner.Add(name, reader.GetString()!);
                        break;
                    case JsonTokenType.True:
                        header.Inner.Add(name, true);
                        break;
                    case JsonTokenType.False:
                        header.Inner.Add(name, false);
                        break;
                    case JsonTokenType.Null:
                        header.Inner.Add(name);
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64(out long longValue))
                        {
                            header.Inner.Add(name, longValue);
                        }
                        else
                        {
                            header.Inner.Add(name, reader.GetDouble());
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

            return header;
        }
    }
}
