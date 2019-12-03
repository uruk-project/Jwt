// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        public static JwtHeader ParseHeader(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }

            return ReadJwtHeader(ref reader);
        }

        internal static JwtHeader ReadJwtHeader(ref Utf8JsonReader reader)
        {
            var current = new JwtObject(3);
            var header = new JwtHeader(current);
            while (reader.Read())
            {
                if (!(reader.TokenType is JsonTokenType.PropertyName))
                {
                    break;
                }

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
                                /* alg */
                                case 6777953u:
                                    var alg = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
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
                                        current.Add(new JwtProperty(WellKnownProperty.Alg, Encoding.UTF8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* enc */
                                case 6516325u:
                                    var enc = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
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
                                        current.Add(new JwtProperty(WellKnownProperty.Enc, Encoding.UTF8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* zip */
                                case 7367034u:
                                    var zip = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
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
                                        current.Add(new JwtProperty(WellKnownProperty.Zip, Encoding.UTF8.GetBytes(reader.GetString())));
                                    }

                                    continue;
                                /* cty */
                                case 7959651u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Cty, Encoding.UTF8.GetBytes(reader.GetString())));
                                    continue;
                                /* typ */
                                case 7371124u:
                                    // TODO : Fix when the Utf8JsonReader will allow
                                    // to read an unescaped string without allocating a string
                                    current.Add(new JwtProperty(WellKnownProperty.Typ, Encoding.UTF8.GetBytes(reader.GetString())));
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
