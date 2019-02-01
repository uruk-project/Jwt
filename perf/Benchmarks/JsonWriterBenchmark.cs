#if NETCOREAPP3_0
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JsonWriterBenchmark
    {
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        static IDictionary<string, object> dictionary = new Dictionary<string, object>()
        {
            { "sub", "sub value" },
            { "jti", "1234567890" },
            { "exp", 12345678 },
            //{ "aud", "https://example.org" },
            { "aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 }
        };

        static IDictionary<string, object> dictionaryMedium = new Dictionary<string, object>()
        {
            { "sub", "sub value" },
            { "jti", "1234567890" },
            { "exp", 12345678 },
            { "aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 },
            { "claim0", "".PadRight(100, 'a') },
            { "claim1", "".PadRight(100, 'b') },
            { "claim2", "".PadRight(100, 'c') },
            { "claim3", "".PadRight(100, 'd') },
            { "claim4", "".PadRight(100, 'e') },
            { "claim5", "".PadRight(100, 'f') },
            { "claim6", "".PadRight(100, 'g') },
            { "claim7", "".PadRight(100, 'h') },
            { "claim8", "".PadRight(100, 'i') },
            { "claim9", "".PadRight(100, 'j') }
        };

        static JObject json = JObject.FromObject(dictionary);

        static JObject jsonMedium = JObject.FromObject(dictionaryMedium);

        static readonly dynamic dyn = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789
        };

        static readonly dynamic dynMedium = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789,
            claim0 = "".PadRight(100, 'a'),
            claim1 = "".PadRight(100, 'b'),
            claim2 = "".PadRight(100, 'c'),
            claim3 = "".PadRight(100, 'd'),
            claim4 = "".PadRight(100, 'e'),
            claim5 = "".PadRight(100, 'f'),
            claim6 = "".PadRight(100, 'g'),
            claim7 = "".PadRight(100, 'h'),
            claim8 = "".PadRight(100, 'i'),
            claim9 = "".PadRight(100, 'j')
        };

        private static readonly DescriptorDictionary payload = new DescriptorDictionary(json);
        private static readonly DescriptorDictionary payloadMedium = new DescriptorDictionary(jsonMedium);

        public JsonWriterBenchmark()
        {
            New();
            Old();
        }

        [Benchmark(Baseline = true)]
        public ReadOnlySequence<byte> New()
        {
            return JwtDescriptor.Serialize(payloadMedium);
        }

        [Benchmark]
        public string Legacy()
        {
            StringWriter sw = new StringWriter(new StringBuilder(256), CultureInfo.InvariantCulture);
            using (JsonTextWriter writer = new JsonTextWriter(sw))
            {
                writer.WriteStartObject();
                for (int i = 0; i < payloadMedium.Count; i++)
                {
                    var property = payloadMedium[i];
#if NETSTANDARD2_0
                    writer.WritePropertyName(EncodingHelper.GetUtf8String(property.Utf8Name.Span));
#else
                    writer.WritePropertyName(Encoding.UTF8.GetString(property.Utf8Name.Span));
#endif
                    switch (property.Type)
                    {
                        case JwtTokenType.Object:
                            var jObject = (JObject)property.Value;
                            jObject.WriteTo(writer);
                            break;
                        case JwtTokenType.Array:
                            var jArray = (JArray)property.Value;
                            jArray.WriteTo(writer);
                            break;
                        case JwtTokenType.Integer:
                            writer.WriteValue((long)property.Value);
                            break;
                        case JwtTokenType.Float:
                            writer.WriteValue((double)property.Value);
                            break;
                        case JwtTokenType.String:
                            writer.WriteValue((string)property.Value);
                            break;
                        case JwtTokenType.Boolean:
                            writer.WriteValue((bool)property.Value);
                            break;
                        case JwtTokenType.Null:
                            writer.WriteNull();
                            break;
                        default:
                            break;
                    }
                }

                writer.WriteEndObject();
                return sw.ToString();
            }
        }

        [Benchmark]
        public string Old()
        {
            return JsonConvert.SerializeObject(jsonMedium, Formatting.None, serializerSettings);
        }
    }
}
#endif