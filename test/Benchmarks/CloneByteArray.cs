using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Attributes.Jobs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Performance
{
    [CoreJob]
    [MemoryDiagnoser]
    public class CloneByteArray
    {
        [Params(32, 1024, 1048576)]
        public int Size;

        private byte[] data;

        [GlobalSetup]
        public void Setup()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                data = new byte[Size];
                rnd.GetBytes(data);
            }
        }

        [Benchmark(Baseline = true)]
        public byte[] Clone()
        {
            return (byte[])data.Clone();
        }
        
        [Benchmark]
        public byte[] ArrayCopyTo()
        {
            var clone = new byte[data.Length];
            data.CopyTo(clone, 0);
            return clone;
        }
    }
}
