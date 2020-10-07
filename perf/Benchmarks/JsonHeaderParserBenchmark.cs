using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;

namespace JsonWebToken.Performance
{
#if NETCOREAPP3_1 
    [MemoryDiagnoser]
    public class JsonHeaderParserBenchmark
    {
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public JwtHeader Old(byte[] data)
        {
            return JwtHeaderParser.ParseHeader(data, TokenValidationPolicy.NoValidation);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public JwtHeader New(byte[] data)
        {
            return JsonHeaderParserSlow.ParseHeaderSlow(data);
        }
        public IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
            yield return Encoding.UTF8.GetBytes("{\"unk\":\"unknow value\",\"x\":123}");
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"unk\":\"unknow value\",\"x\":123}");
        }
    }

    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static partial class JsonHeaderParserSlow
    {

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static JwtHeader ParseHeaderSlow(ReadOnlySpan<byte> buffer)
        {
            return ReadHeaderSlow(buffer);
        }

        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        internal static JwtHeader ReadHeaderSlow(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, isFinalBlock: true, state: default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new FormatException("MalformedJson");
            }

            return ReadJwtHeaderSlow(ref reader);
        }

        internal static JwtHeader ReadJwtHeaderSlow(ref Utf8JsonReader reader)
        {
            var current = new JwtObject(3);
            var header = new JwtHeader(current);
            while (reader.Read())
            {
                if (!(reader.TokenType is JsonTokenType.PropertyName))
                {
                    break;
                }

                if (reader.ValueTextEquals(HeaderParameters.AlgUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

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
                }
                else if (reader.ValueTextEquals(HeaderParameters.EncUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

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
                }
                else if (reader.ValueTextEquals(HeaderParameters.CtyUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

                    current.Add(new JwtProperty(WellKnownProperty.Cty, Encoding.UTF8.GetBytes(reader.GetString())));
                }
                else if (reader.ValueTextEquals(HeaderParameters.TypUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

                    current.Add(new JwtProperty(WellKnownProperty.Typ, Encoding.UTF8.GetBytes(reader.GetString())));
                }
                else if (reader.ValueTextEquals(HeaderParameters.KidUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

                    current.Add(new JwtProperty(WellKnownProperty.Kid, reader.GetString()));
                }
                else if (reader.ValueTextEquals(HeaderParameters.ZipUtf8) && reader.Read())
                {
                    if (!(reader.TokenType is JsonTokenType.String))
                    {
                        break;
                    }

                    var zip = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                    if (CompressionAlgorithm.TryParse(zip, out var compressionAlgorithm))
                    {
                        current.Add(new JwtProperty(compressionAlgorithm));
                    }
                    else if (CompressionAlgorithm.TryParseSlow(ref reader, out compressionAlgorithm))
                    {
                        current.Add(new JwtProperty(compressionAlgorithm));
                    }
                    else
                    {
                        // TODO : Fix when the Utf8JsonReader will allow
                        // to read an unescaped string without allocating a string
                        current.Add(new JwtProperty(WellKnownProperty.Zip, Encoding.UTF8.GetBytes(reader.GetString())));
                    }
                }
                else
                {
                    var name = reader.GetString();
                    reader.Read();
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject:
                            current.Add(name, JsonParser.ReadJsonObject(ref reader));
                            break;
                        case JsonTokenType.StartArray:
                            current.Add(name, JsonParser.ReadJsonArray(ref reader));
                            break;
                        case JsonTokenType.String:
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
                                    throw new FormatException($"NotSupportedNumberValue {Encoding.UTF8.GetBytes(name)}");
                                }
                            }
                            break;
                        default:
                            throw new FormatException("MalformedJson");
                    }
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                throw new FormatException("MalformedJson");
            }

            return header;
        }
    }
#endif
}