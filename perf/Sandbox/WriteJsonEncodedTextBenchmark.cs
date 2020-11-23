using System;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class WriteJsonEncodedTextBenchmark
    {
        private static readonly PooledByteBufferWriter buffer = new PooledByteBufferWriter();
        private static Utf8JsonWriter writer = new Utf8JsonWriter(buffer, Constants.NoJsonValidation);
        private static ReadOnlySpan<byte> propertyNameSegment => new byte[] { (byte)'s', (byte)'t', (byte)'r', (byte)'i', (byte)'n', (byte)'g' };
        private static ReadOnlySpan<byte> propertyValueSegment => new byte[] { (byte)'t', (byte)'h', (byte)'i', (byte)'s', (byte)' ', (byte)'i', (byte)'s', (byte)' ', (byte)'a', (byte)' ', (byte)'s', (byte)'t', (byte)'r', (byte)'i', (byte)'n', (byte)'g', (byte)' ', (byte)'v', (byte)'a', (byte)'l', (byte)'u', (byte)'e' };
        private static readonly string propertyNameString = "string";
        private static readonly string propertyValueString = "this is a string value.";
        private static readonly JsonEncodedText propertyNameJsonEncodedText = JsonEncodedText.Encode(propertyNameString);
        private static readonly JsonEncodedText propertyValueJsonEncodedText = JsonEncodedText.Encode(propertyValueString);
        private static readonly string propertyNameNeedEscapeString = "str+ing";
        private static readonly string propertyValueEscapeString = "this is a + string value.";
        private static readonly JsonEncodedText propertyNameEscapeJsonEncodedText = JsonEncodedText.Encode(propertyNameNeedEscapeString);
        private static readonly JsonEncodedText propertyValueEscapeJsonEncodedText = JsonEncodedText.Encode(propertyValueEscapeString);

        [Benchmark(Baseline = true)]
        public void Write_String()
        {
            writer.Reset();
            writer.WriteString(propertyNameString, propertyValueString);
        }

        [Benchmark]
        public void Write_JsonEncodedText()
        {
            writer.Reset();
            writer.WriteString(propertyNameJsonEncodedText, propertyValueJsonEncodedText);
        }

        [Benchmark]
        public void Write_JsonEncodedText_Encoded()
        {
            writer.Reset();
            writer.WriteString(propertyNameJsonEncodedText.EncodedUtf8Bytes, propertyValueJsonEncodedText);
        }

        [Benchmark]
        public void Write_SegmentData()
        {
            writer.Reset();
            writer.WriteString(propertyNameSegment, propertyValueSegment);
        }

        [Benchmark]
        public void Write_JsonEncodedText_Live()
        {
            writer.Reset();
            writer.WriteString(JsonEncodedText.Encode(propertyNameString), JsonEncodedText.Encode(propertyValueString));
        }

        [Benchmark]
        public void Write_String_NeedEscape()
        {
            writer.Reset();
            writer.WriteString(propertyNameString, propertyValueString);
        }

        [Benchmark]
        public void Write_JsonEncodedText_NeedEscape()
        {
            writer.Reset();
            writer.WriteString(propertyNameEscapeJsonEncodedText, propertyValueEscapeJsonEncodedText);
        }

        [Benchmark]
        public void Write_JsonEncodedText_NeedEscape_Encoded()
        {
            writer.Reset();
            writer.WriteString(propertyNameEscapeJsonEncodedText.EncodedUtf8Bytes, propertyValueEscapeJsonEncodedText);
        }

        [Benchmark]
        public void Write_JsonEncodedText_NeedEscape_Live()
        {
            writer.Reset();
            writer.WriteString(JsonEncodedText.Encode(propertyNameNeedEscapeString), JsonEncodedText.Encode(propertyValueEscapeString));
        }
    }
}
