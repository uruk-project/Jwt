using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class SignatureParserBenchmark
    {
        //[Benchmark(Baseline = false, OperationsPerInvoke = 16)]
        //[ArgumentsSource(nameof(GetData))]
        //public bool New(ReadOnlySpan<byte> data)
        //{
        //    var reader = new Utf8JsonReader(data);
        //    reader.Read();
        //    reader.Read();
        //    SignatureAlgorithm.TryParse(ref reader, out var algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //    return SignatureAlgorithm.TryParse(ref reader, out algorithm);
        //}

        [Benchmark(OperationsPerInvoke = 16, Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public bool Old_WithEscaping(ReadOnlySpan<byte> data)
        {
            var reader = new Utf8JsonReader(data);
            reader.Read();
            reader.Read();
            var value = Encoding.UTF8.GetBytes(reader.GetString());
            SignatureAlgorithm.TryParse(value, out var algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            return SignatureAlgorithm.TryParse(value, out algorithm);
        }

        [Benchmark(OperationsPerInvoke = 16, Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public bool Old_WithoutEscaping(ReadOnlySpan<byte> data)
        {
            var reader = new Utf8JsonReader(data);
            reader.Read();
            reader.Read();
            var value = reader.ValueSpan;
            SignatureAlgorithm.TryParse(value, out var algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            SignatureAlgorithm.TryParse(value, out algorithm);
            return SignatureAlgorithm.TryParse(value, out algorithm);
        }

        //[Benchmark(OperationsPerInvoke = 16)]
        //[ArgumentsSource(nameof(GetData))]
        //public bool Old2_WithoutEscaping(ReadOnlySpan<byte> data)
        //{
        //    var reader = new Utf8JsonReader(data);
        //    reader.Read();
        //    reader.Read();
        //    var value = reader.ValueSpan;
        //    SignatureAlgorithm.TryParse2(value, out var algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    SignatureAlgorithm.TryParse2(value, out algorithm);
        //    return SignatureAlgorithm.TryParse2(value, out algorithm);
        //}


        //[Benchmark(OperationsPerInvoke = 16)]
        //[ArgumentsSource(nameof(GetData))]
        //public bool Old3_WithoutEscaping(ReadOnlySpan<byte> data)
        //{
        //    var reader = new Utf8JsonReader(data);
        //    reader.Read();
        //    reader.Read();
        //    var value = reader.ValueSpan;
        //    SignatureAlgorithm.TryParse3(value, out var algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    SignatureAlgorithm.TryParse3(value, out algorithm);
        //    return SignatureAlgorithm.TryParse3(value, out algorithm);
        //}
        //[Benchmark(OperationsPerInvoke = 16)]
        //[ArgumentsSource(nameof(GetData))]
        //public bool Old4_WithoutEscaping(ReadOnlySpan<byte> data)
        //{
        //    var reader = new Utf8JsonReader(data);
        //    reader.Read();
        //    reader.Read();
        //    var value = reader.ValueSpan;
        //    SignatureAlgorithm.TryParse4(value, out var algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    SignatureAlgorithm.TryParse4(value, out algorithm);
        //    return SignatureAlgorithm.TryParse4(value, out algorithm);
        //}
        //[Benchmark(OperationsPerInvoke = 16)]
        //[ArgumentsSource(nameof(GetData))]
        //public bool Old5_WithoutEscaping(ReadOnlySpan<byte> data)
        //{
        //    var reader = new Utf8JsonReader(data);
        //    reader.Read();
        //    reader.Read();
        //    var value = reader.ValueSpan;
        //    SignatureAlgorithm.TryParse5(value, out var algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    SignatureAlgorithm.TryParse5(value, out algorithm);
        //    return SignatureAlgorithm.TryParse5(value, out algorithm);
        //}


        public IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.HmacSha256.Name + "\"");
            //yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.EcdsaSha256.Name + "\"");
            //yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.RsaSha256.Name + "\"");
            //yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.RsaSsaPssSha256.Name + "\"");
            //yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.RsaSsaPssSha384.Name + "\"");
            //yield return Encoding.UTF8.GetBytes("{\"alg\":\"" + SignatureAlgorithm.None.Name + "\"");
            yield return Encoding.UTF8.GetBytes("{\"alg\":\"fake\"");
        }
    }
}