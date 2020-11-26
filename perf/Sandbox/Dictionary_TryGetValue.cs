using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Performance
{
#nullable disable
    [MemoryDiagnoser]
    public class Dictionary_TryGetValue
    {
        private readonly Dictionary<int, Signer> _dictionary = new Dictionary<int, Signer>();
        private readonly ConcurrentDictionary<int, Signer> _concurrentDictionary = new ConcurrentDictionary<int, Signer>();
        private readonly CryptographicStoreOld<Signer> _cryptoStore = new CryptographicStoreOld<Signer>();
        private readonly CryptographicStore<Signer> _cryptoStore2 = new CryptographicStore<Signer>();

        private int id;

        // property with public setter
        [Params(1, /*2, 4, 8,*/ 16, 32)]
        public int Count { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            var key = SymmetricJwk.GenerateKey(256);
            var rsaKey = RsaJwk.GeneratePrivateKey(2048);
            var ecKey = ECJwk.GeneratePrivateKey(EllipticalCurve.P256);
            for (int i = 0; i < Count; i++)
            {
                key.TryGetSigner(SignatureAlgorithm.HmacSha256, out var signer);
                id = i;
                _dictionary.Add(id, signer);
                _concurrentDictionary.TryAdd(id, signer);
                _cryptoStore.TryAdd(id, signer);
                _cryptoStore2.TryAdd(id, signer);
            }
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

        [Benchmark]
        public void CryptoStore2()
        {
            _cryptoStore2.TryGetValue(id, out var value);
        }
    }


    /// <summary>
    /// Previous implementations of <see cref="CryptographicStore{TValue}"/>.
    /// </summary>
    /// <typeparam name="TValue"></typeparam>
    public sealed class CryptographicStoreOld<TValue> : IDisposable where TValue : class, IDisposable
    {
        private const int HashCollisionThreshold = 100;
        private const int StartOfFreeList = -3;

        private int[] _buckets;
        private Entry[] _entries;
        private int _count;
        private int _freeList;
        private int _freeCount;

        private struct Entry
        {
            // 0-based index of next entry in chain: -1 means end of chain
            // also encodes whether this entry _itself_ is part of the free list by changing sign and subtracting 3,
            // so -2 means end of free list, -3 means index 0 but on free list, -4 means index 1 but on free list, etc.
            public int next;
            public int key;           // Key of entry
            public TValue value;         // Value of entry
        }

        /// <summary>
        /// Gets the count of elements.
        /// </summary>
        public int Count => _count;

        /// <summary>
        /// Gets the element at index <paramref name="index"/>.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public TValue this[int index] => _entries?[index].value;

        /// <summary>
        /// Tries to get the <paramref name="value"/> withe the <paramref name="key"/> as key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(int key, out TValue value)
        {
            int i = -1;
            int[] buckets = _buckets;
            Entry[] entries = _entries!;
            if (buckets != null)
            {
                int collisionCount = 0;

                Debug.Assert(entries != null, "expected entries to be != null");
                uint hashCode = (uint)key;
                // Value in _buckets is 1-based
                i = buckets[hashCode % (uint)buckets.Length] - 1;
                do
                {
                    // Should be a while loop https://github.com/dotnet/coreclr/issues/15476
                    // Test in if to drop range check for following array access
                    if ((uint)i >= (uint)entries.Length || entries[i].key == key)
                    {
                        break;
                    }

                    i = entries[i].next;
                    if (collisionCount >= entries.Length)
                    {
                        // The chain of entries forms a loop; which means a concurrent update has happened.
                        // Break out of the loop and throw, rather than looping forever.
                        throw new InvalidOperationException("Concurrent operations not supported");
                    }
                    collisionCount++;
                } while (true);
            }

            if (i >= 0)
            {
                value = entries[i].value;
                return true;
            }

            value = null;
            return false;
        }

        /// <summary>
        /// Tries to add the <paramref name="value"/> with <paramref name="key"/> as key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryAdd(int key, TValue value)
        {
            if (_buckets is null)
            {
                int size = GetPrime(0);

                _freeList = -1;
                _buckets = new int[size];
                _entries = new Entry[size];
            }

            Debug.Assert(_buckets != null);

            Entry[] entries = _entries!;
            Debug.Assert(entries != null, "expected entries to be non-null");

            uint hashCode = (uint)key;

            int collisionCount = 0;
            ref int bucket = ref _buckets[hashCode % (uint)_buckets.Length];
            // Value in _buckets is 1-based
            int i = bucket - 1;

            do
            {
                // Should be a while loop https://github.com/dotnet/coreclr/issues/15476
                // Test uint in if rather than loop condition to drop range check for following array access
                if ((uint)i >= (uint)entries.Length)
                {
                    break;
                }

                if (entries[i].key == key)
                {
                    return false;
                }

                i = entries[i].next;
                if (collisionCount >= entries.Length)
                {
                    // The chain of entries forms a loop; which means a concurrent update has happened.
                    // Break out of the loop and throw, rather than looping forever.
                    throw new InvalidOperationException("Concurrent operations not supported");
                }

                collisionCount++;
            } while (true);
            bool updateFreeList = false;
            int index;
            if (_freeCount > 0)
            {
                index = _freeList;
                updateFreeList = true;
                _freeCount--;
            }
            else
            {
                int count = _count;
                if (count == entries.Length)
                {
                    Resize();
                    bucket = ref _buckets[hashCode % (uint)_buckets.Length];
                }

                index = count;
                _count = count + 1;
                entries = _entries!;
            }

            ref Entry entry = ref entries[index];
            if (updateFreeList)
            {
                Debug.Assert((StartOfFreeList - entries[_freeList].next) >= -1, "shouldn't overflow because `next` cannot underflow");
                _freeList = StartOfFreeList - entries[_freeList].next;
            }

            // Value in _buckets is 1-based
            entry.next = bucket - 1;
            entry.key = key;
            entry.value = value;
            // Value in _buckets is 1-based
            bucket = index + 1;

            // Value types never rehash
            if (collisionCount > HashCollisionThreshold) // TODO-NULLABLE: default(T) == null warning (https://github.com/dotnet/roslyn/issues/34757)
            {
                Resize(entries.Length);
            }

            return true;
        }

        /// <summary>
        /// Tries to remove the <paramref name="key"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool TryRemove(int key)
        {
            int[] buckets = _buckets;
            if (buckets != null)
            {
                Entry[] entries = _entries!;
                int collisionCount = 0;

                Debug.Assert(entries != null, "entries should be non-null");
                uint hashCode = (uint)key; // TODO-NULLABLE: Remove ! when [DoesNotReturn] respected
                uint bucket = hashCode % (uint)buckets.Length;
                int last = -1;
                // Value in buckets is 1-based
                int i = buckets[bucket] - 1;
                while (i >= 0)
                {
                    ref Entry entry = ref entries[i];

                    if (entry.key == key)
                    {
                        if (last < 0)
                        {
                            // Value in buckets is 1-based
                            buckets[bucket] = entry.next + 1;
                        }
                        else
                        {
                            entries[last].next = entry.next;
                        }

                        Debug.Assert((StartOfFreeList - _freeList) < 0, "shouldn't underflow because max hashtable length is MaxPrimeArrayLength = 0x7FEFFFFD(2146435069) _freelist underflow threshold 2147483646");

                        entry.next = StartOfFreeList - _freeList;
                        entry.value = null;
                        _freeList = i;
                        _freeCount++;
                        return true;
                    }

                    last = i;
                    i = entry.next;
                    if (collisionCount >= entries.Length)
                    {
                        // The chain of entries forms a loop; which means a concurrent update has happened.
                        // Break out of the loop and throw, rather than looping forever.
                        throw new InvalidOperationException("Concurrent operations not supported");
                    }
                    collisionCount++;
                }
            }
            return false;
        }

        private void Resize() => Resize(ExpandPrime(_count));

        private void Resize(int newSize)
        {
            Debug.Assert(_entries != null, "_entries should be non-null");
            Debug.Assert(newSize >= _entries.Length);

            int[] buckets = new int[newSize];
            Entry[] entries = new Entry[newSize];

            int count = _count;
            Array.Copy(_entries, 0, entries, 0, count);

            for (int i = 0; i < count; i++)
            {
                if (entries[i].next >= -1)
                {
                    uint bucket = (uint)entries[i].key % (uint)newSize;
                    // Value in _buckets is 1-based
                    entries[i].next = buckets[bucket] - 1;
                    // Value in _buckets is 1-based
                    buckets[bucket] = i + 1;
                }
            }

            _buckets = buckets;
            _entries = entries;
        }

        /// <inheritsdoc />
        public void Dispose()
        {
            var entries = _entries;
            if (!(entries is null))
            {
                for (int i = 0; i < _count; i++)
                {
                    entries[i].value?.Dispose();
                }
            }
        }

        private const int MaxPrimeArrayLength = 0x7FEFFFFD;
        private const int HashPrime = 101;
        private static readonly int[] primes = {
            3, 7, 11, 17, 23, 29, 37, 47, 59, 71, 89, 107, 131, 163, 197, 239, 293, 353, 431, 521, 631, 761, 919,
            1103, 1327, 1597, 1931, 2333, 2801, 3371, 4049, 4861, 5839, 7013, 8419, 10103, 12143, 14591,
            17519, 21023, 25229, 30293, 36353, 43627, 52361, 62851, 75431, 90523, 108631, 130363, 156437,
            187751, 225307, 270371, 324449, 389357, 467237, 560689, 672827, 807403, 968897, 1162687, 1395263,
            1674319, 2009191, 2411033, 2893249, 3471899, 4166287, 4999559, 5999471, 7199369 };

        private static int GetPrime(int min)
        {
            for (int i = 0; i < primes.Length; i++)
            {
                int prime = primes[i];
                if (prime >= min)
                {
                    return prime;
                }
            }

            //outside of our predefined table. 
            //compute the hard way. 
            for (int i = (min | 1); i < int.MaxValue; i += 2)
            {
                if (IsPrime(i) && ((i - 1) % HashPrime != 0))
                {
                    return i;
                }
            }

            return min;
        }

        private static int ExpandPrime(int oldSize)
        {
            int newSize = 2 * oldSize;

            // Allow the hashtables to grow to maximum possible size (~2G elements) before encountering capacity overflow.
            // Note that this check works even when _items.Length overflowed thanks to the (uint) cast
            if ((uint)newSize > MaxPrimeArrayLength && MaxPrimeArrayLength > oldSize)
            {
                Debug.Assert(MaxPrimeArrayLength == GetPrime(MaxPrimeArrayLength), "Invalid MaxPrimeArrayLength");
                return MaxPrimeArrayLength;
            }

            return GetPrime(newSize);
        }

        private static bool IsPrime(int candidate)
        {
            if ((candidate & 1) != 0)
            {
                int limit = (int)Math.Sqrt(candidate);
                for (int divisor = 3; divisor <= limit; divisor += 2)
                {
                    if ((candidate % divisor) == 0)
                    {
                        return false;
                    }
                }

                return true;
            }

            return (candidate == 2);
        }
    }
}
