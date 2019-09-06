using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JsonHeaderParserBenchmark
    {
        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public JwtHeader Old(byte[] data)
        {
            return JsonHeaderParser.ParseHeader(data);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public JwtHeader New(byte[] data)
        {
            return JsonHeaderParser.ParseHeader2(data);
        }

        public IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
            yield return Encoding.UTF8.GetBytes("{\"unk\":\"unknow value\",\"x\":123}");
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"unk\":\"unknow value\",\"x\":123}");
        }
    }

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

        private static readonly JwtObject payload = Tokens.ToJwtObject(json);
        private static readonly JwtObject payloadMedium = Tokens.ToJwtObject(jsonMedium);
        private static readonly ArrayBufferWriter _output = new ArrayBufferWriter();

        [Benchmark(Baseline = false)]
        public byte[] New()
        {
            return payloadMedium.Serialize();
        }

        [Benchmark]
        public void New2()
        {
            _output.Clear();
            payloadMedium.Serialize(_output);
        }

        [Benchmark]
        public string Old()
        {
            return JsonConvert.SerializeObject(jsonMedium, Formatting.None, serializerSettings);
        }
    }
}