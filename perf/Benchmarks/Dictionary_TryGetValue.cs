using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class Dictionary_TryGetValue
    {
        private readonly Dictionary<int, Signer> _dictionary = new Dictionary<int, Signer>();
        private readonly ConcurrentDictionary<int, Signer> _concurrentDictionary = new ConcurrentDictionary<int, Signer>();
        private readonly CryptographicStore<Signer> _cryptoStore = new CryptographicStore<Signer>();

        private static readonly int id = SignatureAlgorithm.HmacSha256.Id;

        public Dictionary_TryGetValue()
        {
            var key = SymmetricJwk.GenerateKey(256); ;
            var signer = key.TryCreateSigner(SignatureAlgorithm.HmacSha256);
            _dictionary.Add(signer.Algorithm.Id, signer);
            _concurrentDictionary.TryAdd(signer.Algorithm.Id, signer);
            _cryptoStore.TryAdd(signer.Algorithm.Id, signer);
        }

        [Benchmark(Baseline = true)]
        public void Dictionary()
        {
            _dictionary.TryGetValue(id, out var value);
        }

        [Benchmark]
        public void ConcurrentDictionary()
        {
            _concurrentDictionary.TryGetValue(id, out var value);
        }

        [Benchmark]
        public void CryptoStore()
        {
            _cryptoStore.TryGetValue(id, out var value);
        }
    }
}
