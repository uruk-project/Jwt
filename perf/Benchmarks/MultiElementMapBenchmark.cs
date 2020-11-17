//using System.Collections;
//using System.Collections.Generic;
//using System.Diagnostics.CodeAnalysis;
//using System.Runtime.CompilerServices;
//using System.Text.Json;
//using BenchmarkDotNet.Attributes;
//using BenchmarkDotNet.Diagnosers;
//using JsonWebToken.Internal;

//namespace JsonWebToken.Performance
//{
//    [MemoryDiagnoser]
//    public class MultiElementMapBenchmark
//    {
//        [Benchmark(Baseline = true)]
//        public void AddSafe()
//        {
//            MultiElementMap map = new MultiElementMap(5);
//            map.UnsafeStore(0, new JwtMember());
//            map.UnsafeStore(1, new JwtMember());
//            map.UnsafeStore(2, new JwtMember());
//            map.UnsafeStore(3, new JwtMember());
//            map.UnsafeStore(4, new JwtMember());
//            var m = (Map)map;
//            for (int i = 5; i < 16; i++)
//            {
//                m.TryAdd(new JwtMember(), out m);
//            }
//        }

//           [Benchmark(Baseline = false)]
//        public void AddUnsafe()
//        {
//            MultiElementMapUnsafe map = new MultiElementMapUnsafe(5);
//            map.UnsafeStore(0, new JwtMember());
//            map.UnsafeStore(1, new JwtMember());
//            map.UnsafeStore(2, new JwtMember());
//            map.UnsafeStore(3, new JwtMember());
//            map.UnsafeStore(4, new JwtMember());
//            var m = (Map)map;
//            for (int i = 5; i < 16; i++)
//            {
//                m.TryAdd(new JwtMember(), out m);
//            }
//        }


//        private interface Map : IEnumerable<JwtMember>
//        {
//            public int Count { get; }

//            public bool TryAdd(JwtMember value, out Map map);

//            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMember value);

//            public bool ContainsKey(string key);

//            void WriteTo(Utf8JsonWriter writer);

//            Map Merge(Map map);
//        }
//        private sealed class MultiElementMap : Map
//        {
//            private const int MaxMultiElements = 16;
//            private readonly JwtMember[] _keyValues;
//            private int _count;

//            public int Count => _count;

//            public MultiElementMap(int count)
//            {
//                _keyValues = new JwtMember[MaxMultiElements];
//                _count = count;
//            }

//            public void UnsafeStore(int index, JwtMember value)
//            {
//                _keyValues[index] = value;
//            }

//            public bool TryAdd(JwtMember value, out Map map)
//            {
//                for (int i = 0; i < _count - 1; i++)
//                {
//                    if (value.Name == _keyValues[i].Name)
//                    {
//                        // The key is in the map. 
//                        map = this;
//                        return false;
//                    }
//                }

//                if (_count < _keyValues.Length)
//                {
//                    UnsafeStore(_count, value);
//                    _count++;
//                    map = this;
//                    return true;
//                }

//                // Otherwise, upgrade to a many map.
//                var many = new ManyElementMap(MaxMultiElements + 1);
//                foreach (JwtMember pair in _keyValues)
//                {
//                    many[pair.Name] = pair;
//                }

//                many[value.Name] = value;
//                map = many;
//                return true;
//            }

//            public bool TryGetValue(string key, out JwtMember value)
//            {
//                foreach (JwtMember pair in _keyValues)
//                {
//                    if (key == pair.Name)
//                    {
//                        value = pair;
//                        return true;
//                    }
//                }

//                value = default;
//                return false;
//            }

//            public void WriteTo(Utf8JsonWriter writer)
//            {
//                for (int i = 0; i < _count; i++)
//                {
//                    JwtMember pair = _keyValues[i];
//                    pair.WriteTo(writer);
//                }
//            }

//            public bool ContainsKey(string key)
//            {
//                foreach (JwtMember pair in _keyValues)
//                {
//                    if (key == pair.Name)
//                    {
//                        return true;
//                    }
//                }

//                return false;
//            }

//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return new ObjectEnumerator(this);
//            }

//            IEnumerator IEnumerable.GetEnumerator()
//                => GetEnumerator();

//            public Map Merge(Map map)
//            {
//                foreach (var item in _keyValues)
//                {
//                    map.TryAdd(item, out map);
//                }

//                return map;
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            public struct ObjectEnumerator : IEnumerator<JwtMember>
//            {
//                private readonly MultiElementMap _map;
//                private int _idx;
//                internal ObjectEnumerator(MultiElementMap map)
//                {
//                    _map = map;
//                    _idx = -1;
//                }

//                /// <inheritdoc />
//                public JwtMember Current
//                {
//                    get
//                    {
//                        return _map._keyValues[_idx];
//                    }
//                }

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                    _idx = 0;
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                {
//                    return ++_idx < _map.Count;
//                }
//            }
//        }
//        private sealed class MultiElementMapUnsafe : Map
//        {
//            private const int MaxMultiElements = 16;
//            private readonly JwtMember[] _keyValues;
//            private int _count;

//            public int Count => _count;

//            public MultiElementMapUnsafe(int count)
//            {
//                _keyValues = new JwtMember[MaxMultiElements];
//                _count = count;
//            }

//            public void UnsafeStore(int index, JwtMember value)
//            {
//                _keyValues[index] = value;
//            }

//            public bool TryAdd(JwtMember value, out Map map)
//            {
//                ref JwtMember member = ref _keyValues[0];
//                for (int i = 0; i < _count - 1; i++)
//                {
//                    if (value.Name == member.Name)
//                    {
//                        // The key is in the map. 
//                        map = this;
//                        return false;
//                    }

//                    member = Unsafe.Add(ref member, 1);
//                }

//                if (_count < _keyValues.Length)
//                {
//                    UnsafeStore(_count, value);
//                    _count++;
//                    map = this;
//                    return true;
//                }

//                // Otherwise, upgrade to a many map.
//                var many = new ManyElementMap(MaxMultiElements + 1);
//                foreach (JwtMember pair in _keyValues)
//                {
//                    many[pair.Name] = pair;
//                }

//                many[value.Name] = value;
//                map = many;
//                return true;
//            }

//            public bool TryGetValue(string key, out JwtMember value)
//            {
//                foreach (JwtMember pair in _keyValues)
//                {
//                    if (key == pair.Name)
//                    {
//                        value = pair;
//                        return true;
//                    }
//                }

//                value = default;
//                return false;
//            }

//            public void WriteTo(Utf8JsonWriter writer)
//            {
//                for (int i = 0; i < _count; i++)
//                {
//                    JwtMember pair = _keyValues[i];
//                    pair.WriteTo(writer);
//                }
//            }

//            public bool ContainsKey(string key)
//            {
//                foreach (JwtMember pair in _keyValues)
//                {
//                    if (key == pair.Name)
//                    {
//                        return true;
//                    }
//                }

//                return false;
//            }

//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return new ObjectEnumerator(this);
//            }

//            IEnumerator IEnumerable.GetEnumerator()
//                => GetEnumerator();

//            public Map Merge(Map map)
//            {
//                foreach (var item in _keyValues)
//                {
//                    map.TryAdd(item, out map);
//                }

//                return map;
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            public struct ObjectEnumerator : IEnumerator<JwtMember>
//            {
//                private readonly MultiElementMapUnsafe _map;
//                private int _idx;
//                internal ObjectEnumerator(MultiElementMapUnsafe map)
//                {
//                    _map = map;
//                    _idx = -1;
//                }

//                /// <inheritdoc />
//                public JwtMember Current
//                {
//                    get
//                    {
//                        return _map._keyValues[_idx];
//                    }
//                }

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                    _idx = 0;
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                {
//                    return ++_idx < _map.Count;
//                }
//            }
//        }

//        private sealed class ManyElementMap : Map
//        {
//            private readonly Dictionary<string, JwtMember> _dictionary;

//            public int Count => _dictionary.Count;

//            public ManyElementMap(int capacity)
//            {
//                _dictionary = new Dictionary<string, JwtMember>(capacity);
//            }

//            public bool TryAdd(JwtMember value, out Map map)
//            {
//                map = this;
//#if NETCOREAPP
//                return _dictionary.TryAdd(value.Name, value);
//#else
//                if (_dictionary.ContainsKey(value.Name))
//                {
//                    return false;
//                }
//                else
//                {
//                    _dictionary[value.Name] = value;
//                    return true;
//                }
//#endif
//            }

//            public bool TryGetValue(string key, out JwtMember value)
//            {
//                var result = _dictionary.TryGetValue(key, out var tmp);
//                value = tmp;
//                return result;
//            }

//            public void WriteTo(Utf8JsonWriter writer)
//            {
//                foreach (KeyValuePair<string, JwtMember> pair in _dictionary)
//                {
//                    pair.Value.WriteTo(writer);
//                }
//            }

//            public bool ContainsKey(string key)
//            {
//                return _dictionary.ContainsKey(key);
//            }

//            public JwtMember this[string key]
//            {
//                get => _dictionary[key];
//                set => _dictionary[key] = value;
//            }

//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _dictionary.Values.GetEnumerator();
//            }

//            IEnumerator IEnumerable.GetEnumerator()
//                => GetEnumerator();

//            public Map Merge(Map map)
//            {
//                foreach (var item in _dictionary.Values)
//                {
//                    map.TryAdd(item, out map);
//                }

//                return map;
//            }
//        }
//    }
//}
