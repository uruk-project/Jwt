// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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
    public static partial class JwtHeaderParser
    {
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

            return ReadJwtHeader(ref reader, policy);
        }

        internal static JwtHeader ReadJwtHeader(ref Utf8JsonReader reader, TokenValidationPolicy policy)
        {
            var current = new JwtObject(3);
            var header = new JwtHeader(current);
            while (reader.Read())
            {
                if (!(reader.TokenType is JsonTokenType.PropertyName))
                {
                    break;
                }

                var name = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                reader.Read();
                var type = reader.TokenType;
                switch (type)
                {
                    case JsonTokenType.StartObject:
                        current.Add(name, JsonParser.ReadJsonObject(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        if (name.Length == 4 && Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) == 1953067619u /* crit */)
                        {
                            var handlers = policy.CriticalHandlers;
                            if (handlers.Count != 0)
                            {
                                header.CriticalHeaderHandlers = new List<KeyValuePair<string, ICriticalHeaderHandler>>(handlers.Count);
                                var criticals = new List<JwtValue>();
                                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                {
                                    string criticalHeader = reader.GetString();
                                    criticals.Add(new JwtValue(criticalHeader));
                                    if (handlers.TryGetValue(criticalHeader, out var handler))
                                    {
                                        header.CriticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, handler));
                                    }
                                    else
                                    {
                                        header.CriticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, null!));
                                    }
                                }

                                if (reader.TokenType != JsonTokenType.EndArray)
                                {
                                    ThrowHelper.ThrowFormatException_MalformedJson("The 'crit' header parameter must be an array of string.");
                                }

                                current.Add(new JwtProperty(name, new JwtArray(criticals)));
                            }
                            else
                            {
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
                            var refName = Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(name)) & 0x00ffffffu;
                            switch (refName)
                            {
                                /* alg */
                                case 6777953u:
                                    var alg = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
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
                                        // TODO : Fix when the Utf8JsonReader will allow
                                        // to read an unescaped string without allocating a string
                                        current.Add(new JwtProperty(WellKnownProperty.Alg, Utf8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* enc */
                                case 6516325u:
                                    var enc = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
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
                                        // TODO : Fix when the Utf8JsonReader will allow
                                        // to read an unescaped string without allocating a string
                                        current.Add(new JwtProperty(WellKnownProperty.Enc, Utf8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* zip */
                                case 7367034u:
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
                                        // TODO : Fix when the Utf8JsonReader will allow
                                        // to read an unescaped string without allocating a string
                                        current.Add(new JwtProperty(WellKnownProperty.Zip, Utf8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* cty */
                                case 7959651u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Cty, Utf8.GetBytes(reader.GetString())));
                                    continue;
                                /* typ */
                                case 7371124u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Typ, Utf8.GetBytes(reader.GetString())));
                                    continue;
                                /* kid */
                                case 6580587u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Kid, reader.GetString()));
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

            return header;
        }
    }
}
