//using System;
//using System.Collections;
//using System.Collections.Generic;
//using System.Diagnostics;
//using BenchmarkDotNet.Attributes;
//using BenchmarkDotNet.Diagnosers;

//namespace JsonWebToken.Performance
//{
//    [MemoryDiagnoser]
//    public class MemberStoreBenchmark
//    {
//        [Params(1, 2, 3, 4, 6, 8, 16, 32)]
//        public int Length { get; set; }

//        [Benchmark(Baseline = true)]
//        public void NoValidation()
//        {
//            var store = MemberStoreNoValidation.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }
//        }
//        [Benchmark(Baseline = false)]
//        public void NoValidationV2()
//        {
//            var store = MemberStoreNoValidationV2.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }
//        }
//        [Benchmark(Baseline = false)]
//        public void NoValidationV3()
//        {
//            var store = MemberStoreNoValidationV3.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }
//        }

//        [Benchmark(Baseline = false)]
//        public void WithoutDuplicate()
//        {
//            var store = MemberStoreWithoutDuplicate.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }
//        }

//        [Benchmark(Baseline = false)]
//        public void WithLateValidation()
//        {
//            var store = MemberStoreNoValidation.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }

//            store.Validate();
//        }

//        [Benchmark(Baseline = false)]
//        public void WithLateValidationNoThrow()
//        {
//            var store = MemberStoreNoValidationNoThrow.CreateSlowGrowingStore();
//            for (int i = 0; i < Length; i++)
//            {
//                store.Add(new JwtMember(i.ToString(), i));
//            }

//            store.Validate();
//        }

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreNoValidationV3 : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationV3 CreateFastGrowingStore()
//                => new MemberStoreNoValidationV3(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationV3 CreateSlowGrowingStore()
//                => new MemberStoreNoValidationV3(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreNoValidationV3(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            public void Validate()
//            {
//                _map.Validate();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map = _map.Add(value);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public IMap Add(JwtMember value);

//                void Validate();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public IMap Add(JwtMember value)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    return newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public IMap Add(JwtMember value)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    return new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public IMap Add(JwtMember value)
//                {
//                    return new TwoElementMap(_value1, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // 1 element, no duplicate
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                internal readonly JwtMember _value1;
//                internal readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public IMap Add(JwtMember value)
//                {
//                    return new ThreeElementMap(this, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                internal readonly TwoElementMap _map2;
//                internal readonly JwtMember _value3;

//                public ThreeElementMap(TwoElementMap map2, JwtMember value3)
//                {
//                    _map2 = map2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public IMap Add(JwtMember value)
//                {
//                    return new FourElementMap(this, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_map2._value1.Name == _map2._value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_map2._value1.Name);
//                    }

//                    if (_map2._value2.Name == _value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_map2._value2.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._map2._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._map2._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly ThreeElementMap _map3;
//                private readonly JwtMember _value4;

//                public FourElementMap(ThreeElementMap map3, JwtMember value4)
//                {
//                    _map3 = map3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public IMap Add(JwtMember value)
//                {
//                    var multi = new MultiElementMap(5);
//                    multi.UnsafeStore(0, _map3._map2._value1);
//                    multi.UnsafeStore(1, _map3._map2._value2);
//                    multi.UnsafeStore(2, _map3._value3);
//                    multi.UnsafeStore(3, _value4);
//                    multi.UnsafeStore(4, value);
//                    return multi;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_map3._map2._value1.Name == _map3._map2._value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_map3._map2._value1.Name);
//                    }

//                    if (_map3._map2._value2.Name == _map3._value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_map3._map2._value2.Name);
//                    }

//                    if (_map3._value3.Name == _value4.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_map3._value3.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._map3._map2._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._map3._map2._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._map3._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public IMap Add(JwtMember value)
//                {
//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        return this;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    return many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        for (int j = 0; j < _count; j++)
//                        {
//                            if (i != j && _keyValues[i].Name == _keyValues[j].Name)
//                            {
//                                ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_keyValues[i].Name);
//                            }
//                        }
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public IMap Add(JwtMember value)
//                {
//                    _dictionary[value.Name] = value;
//                    return this;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // the Dictionary does not allow duplicates       
//                }
//            }
//        }

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreNoValidationV2 : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationV2 CreateFastGrowingStore()
//                => new MemberStoreNoValidationV2(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationV2 CreateSlowGrowingStore()
//                => new MemberStoreNoValidationV2(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreNoValidationV2(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            public void Validate()
//            {
//                _map.Validate();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map = _map.Add(value);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public IMap Add(JwtMember value);

//                void Validate();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public IMap Add(JwtMember value)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    return newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public IMap Add(JwtMember value)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    return new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public IMap Add(JwtMember value)
//                {
//                    return new TwoElementMap(_value1, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // 1 element, no duplicate
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public IMap Add(JwtMember value)
//                {
//                    return new ThreeElementMap(_value1, _value2, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;

//                public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public IMap Add(JwtMember value)
//                {
//                    return new FourElementMap(_value1, _value2, _value3, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value2.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;
//                private readonly JwtMember _value4;

//                public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public IMap Add(JwtMember value)
//                {
//                    var multi = new MultiElementMap(5);
//                    multi.UnsafeStore(0, _value1);
//                    multi.UnsafeStore(1, _value2);
//                    multi.UnsafeStore(2, _value3);
//                    multi.UnsafeStore(3, _value4);
//                    multi.UnsafeStore(4, value);
//                    return multi;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value2.Name);
//                    }

//                    if (_value3.Name == _value4.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value3.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public IMap Add(JwtMember value)
//                {
//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        return this;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    return many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        for (int j = 0; j < _count; j++)
//                        {
//                            if (i != j && _keyValues[i].Name == _keyValues[j].Name)
//                            {
//                                ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_keyValues[i].Name);
//                            }
//                        }
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public IMap Add(JwtMember value)
//                {
//                    _dictionary[value.Name] = value;
//                    return this;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // the Dictionary does not allow duplicates       
//                }
//            }
//        }

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreNoValidation : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidation CreateFastGrowingStore()
//                => new MemberStoreNoValidation(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidation CreateSlowGrowingStore()
//                => new MemberStoreNoValidation(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreNoValidation(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            public void Validate()
//            {
//                _map.Validate();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map.Add(value, out _map);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public void Add(JwtMember value, out IMap map);

//                void Validate();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    map = newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    map = new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                }
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new TwoElementMap(_value1, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // 1 element, no duplicate
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new ThreeElementMap(_value1, _value2, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;

//                public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new FourElementMap(_value1, _value2, _value3, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value2.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;
//                private readonly JwtMember _value4;

//                public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    var multi = new MultiElementMap(5);
//                    multi.UnsafeStore(0, _value1);
//                    multi.UnsafeStore(1, _value2);
//                    multi.UnsafeStore(2, _value3);
//                    multi.UnsafeStore(3, _value4);
//                    multi.UnsafeStore(4, value);
//                    map = multi;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value1.Name);
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value2.Name);
//                    }

//                    if (_value3.Name == _value4.Name)
//                    {
//                        ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_value3.Name);
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        map = this;
//                        return;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    map = many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        for (int j = i + 1; j < _count; j++)
//                        {
//                            if (_keyValues[i].Name == _keyValues[j].Name)
//                            {
//                                ThrowHelper.ThrowInvalidOperationException_DuplicateJsonMember(_keyValues[i].Name);
//                            }
//                        }
//                    }
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = this;
//                    _dictionary[value.Name] = value;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public void Validate()
//                {
//                    // the Dictionary does not allow duplicates       
//                }
//            }
//        }

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreNoValidationNoThrow : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationNoThrow CreateFastGrowingStore()
//                => new MemberStoreNoValidationNoThrow(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationNoThrow CreateSlowGrowingStore()
//                => new MemberStoreNoValidationNoThrow(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreNoValidationNoThrow(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            public void Validate()
//            {
//                _map = _map.Validate();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map.Add(value, out _map);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public void Add(JwtMember value, out IMap map);

//                IMap Validate();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    map = newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    map = new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new TwoElementMap(_value1, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new ThreeElementMap(_value1, _value2, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new OneElementMap(_value1);
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;

//                public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new FourElementMap(_value1, _value2, _value3, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new TwoElementMap(_value2, _value3).Validate();
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        return new TwoElementMap(_value1, _value2);
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;
//                private readonly JwtMember _value4;

//                public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    var multi = new MultiElementMap(5);
//                    multi.UnsafeStore(0, _value1);
//                    multi.UnsafeStore(1, _value2);
//                    multi.UnsafeStore(2, _value3);
//                    multi.UnsafeStore(3, _value4);
//                    multi.UnsafeStore(4, value);
//                    map = multi;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new ThreeElementMap(_value2, _value3, _value4).Validate();
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        return new ThreeElementMap(_value1, _value3, _value4).Validate();
//                    }

//                    if (_value3.Name == _value4.Name)
//                    {
//                        return new ThreeElementMap(_value1, _value2, _value4).Validate();
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        map = this;
//                        return;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    map = many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        for (int j = i + 1; j < _count; j++)
//                        {
//                            if (_keyValues[i].Name == _keyValues[j].Name)
//                            {
//                                _count--;
//                                for (int k = i; k < _count; k++)
//                                {
//                                    _keyValues[k] = _keyValues[k + 1];
//                                }
//                            }
//                        }
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = this;
//                    _dictionary[value.Name] = value;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    // the Dictionary does not allow duplicates
//                    return this;
//                }
//            }
//        }
        

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreNoValidationNoThrowWithHashCode : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationNoThrowWithHashCode CreateFastGrowingStore()
//                => new MemberStoreNoValidationNoThrowWithHashCode(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreNoValidationNoThrowWithHashCode CreateSlowGrowingStore()
//                => new MemberStoreNoValidationNoThrowWithHashCode(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreNoValidationNoThrowWithHashCode(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            public void Validate()
//            {
//                _map = _map.Validate();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map.Add(value, out _map);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public void Add(JwtMember value, out IMap map);

//                IMap Validate();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    map = newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    map = new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new TwoElementMap(_value1, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new ThreeElementMap(_value1, _value2, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new OneElementMap(_value1);
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;

//                public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = new FourElementMap(_value1, _value2, _value3, value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new TwoElementMap(_value2, _value3).Validate();
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        return new TwoElementMap(_value1, _value2);
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;
//                private readonly JwtMember _value4;

//                public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    var multi = new MultiElementMap(5);
//                    multi.UnsafeStore(0, _value1);
//                    multi.UnsafeStore(1, _value2);
//                    multi.UnsafeStore(2, _value3);
//                    multi.UnsafeStore(3, _value4);
//                    multi.UnsafeStore(4, value);
//                    map = multi;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    if (_value1.Name == _value2.Name)
//                    {
//                        return new ThreeElementMap(_value2, _value3, _value4).Validate();
//                    }

//                    if (_value2.Name == _value3.Name)
//                    {
//                        return new ThreeElementMap(_value1, _value3, _value4).Validate();
//                    }

//                    if (_value3.Name == _value4.Name)
//                    {
//                        return new ThreeElementMap(_value1, _value2, _value4).Validate();
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        map = this;
//                        return;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    map = many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        for (int j = i + 1; j < _count; j++)
//                        {
//                            if (_keyValues[i].Name == _keyValues[j].Name)
//                            {
//                                _count--;
//                                for (int k = i; k < _count; k++)
//                                {
//                                    _keyValues[k] = _keyValues[k + 1];
//                                }
//                            }
//                        }
//                    }

//                    return this;
//                }

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = this;
//                    _dictionary[value.Name] = value;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                public IMap Validate()
//                {
//                    // the Dictionary does not allow duplicates
//                    return this;
//                }
//            }
//        }

//        /// <summary>Represents a store for JSON memebers.</summary>
//        /// <remarks>Designed for progressive </remarks>
//        public sealed class MemberStoreWithoutDuplicate : IEnumerable<JwtMember>
//        {
//            /// <summary>
//            /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreWithoutDuplicate CreateFastGrowingStore()
//                => new MemberStoreWithoutDuplicate(FastGrowingEmptyMap.Empty);

//            /// <summary>
//            /// Creates a store that will grow its capacity item by item until 4, 
//            /// then to a <see cref="Array"/> of 16 items.
//            /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
//            /// </summary>
//            /// <returns></returns>
//            public static MemberStoreWithoutDuplicate CreateSlowGrowingStore()
//                => new MemberStoreWithoutDuplicate(SlowGrowingEmptyMap.Empty);

//            private IMap _map;

//            /// <summary>
//            /// Gets the count of elements.
//            /// </summary>
//            public int Count => _map.Count;

//            private MemberStoreWithoutDuplicate(IMap map)
//            {
//                _map = map;
//            }

//            /// <inheritdoc/>
//            public IEnumerator<JwtMember> GetEnumerator()
//            {
//                return _map.GetEnumerator();
//            }

//            /// <summary>
//            /// Tries to add the <paramref name="value"/>.
//            /// </summary>
//            /// <param name="value"></param>
//            /// <returns></returns>
//            public void Add(JwtMember value)
//                => _map.Add(value, out _map);

//            IEnumerator IEnumerable.GetEnumerator()
//            {
//                return GetEnumerator();
//            }

//            private interface IMap : IEnumerable<JwtMember>
//            {
//                public int Count { get; }

//                public void Add(JwtMember value, out IMap map);
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class FastGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    //map = new OneElementMap(value);
//                    var newMap = new MultiElementMap(1);
//                    newMap.UnsafeStore(0, value);
//                    map = newMap;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();
//            }

//            // Instance without any key/value pairs. Used as a singleton.
//            private sealed class SlowGrowingEmptyMap : IMap
//            {
//                public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

//                public int Count => 0;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    // Create a new one-element map to store the key/value pair
//                    map = new OneElementMap(value);
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return EmptyObjectEnumerator.Empty;
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();
//            }

//            /// <summary>
//            ///   An enumerable and enumerator for the properties of a JSON object.
//            /// </summary>
//            [DebuggerDisplay("{Current,nq}")]
//            private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
//            {
//                public static readonly EmptyObjectEnumerator Empty = default;

//                /// <inheritdoc />
//                public JwtMember Current
//                    => default;

//                /// <inheritdoc />
//                public void Dispose()
//                {
//                }

//                /// <inheritdoc />
//                public void Reset()
//                {
//                }

//                /// <inheritdoc />
//                object IEnumerator.Current => Current;


//                /// <inheritdoc />
//                public bool MoveNext()
//                    => false;
//            }

//            private sealed class OneElementMap : IMap
//            {
//                private readonly JwtMember _value1;

//                public OneElementMap(JwtMember value)
//                {
//                    _value1 = value;
//                }

//                public int Count => 1;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (value.Name == _value1.Name)
//                    {
//                        map = new OneElementMap(value);
//                    }
//                    else
//                    {
//                        map = new TwoElementMap(_value1, value);
//                    }
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly OneElementMap _map;
//                    private bool _state;

//                    internal ObjectEnumerator(OneElementMap map)
//                    {
//                        _map = map;
//                        _state = true;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._value1;
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;

//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        bool state = _state;
//                        _state = false;
//                        return state;
//                    }
//                }
//            }

//            private sealed class TwoElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;

//                public TwoElementMap(JwtMember value1, JwtMember value2)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                }

//                public int Count => 2;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (value.Name == _value1.Name)
//                    {
//                        map = new TwoElementMap(value, _value2);
//                    }
//                    else if (value.Name == _value2.Name)
//                    {
//                        map = new TwoElementMap(_value1, value);
//                    }
//                    else
//                    {
//                        map = new ThreeElementMap(_value1, _value2, value);
//                    }
//                }

//                public bool ContainsKey(string key)
//                {
//                    return key == _value1.Name || key == _value2.Name;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly TwoElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(TwoElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else
//                            {
//                                return _map._value2;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 2;
//                    }
//                }
//            }

//            private sealed class ThreeElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;

//                public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                }

//                public int Count => 3;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (value.Name == _value1.Name)
//                    {
//                        map = new ThreeElementMap(value, _value2, _value3);
//                    }
//                    else if (value.Name == _value2.Name)
//                    {
//                        map = new ThreeElementMap(_value1, value, _value3);
//                    }
//                    else if (value.Name == _value3.Name)
//                    {
//                        map = new ThreeElementMap(_value1, _value2, value);
//                    }
//                    else
//                    {
//                        map = new FourElementMap(_value1, _value2, _value3, value);
//                    }
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly ThreeElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(ThreeElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else
//                            {
//                                return _map._value3;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 3;
//                    }
//                }
//            }

//            private sealed class FourElementMap : IMap
//            {
//                private readonly JwtMember _value1;
//                private readonly JwtMember _value2;
//                private readonly JwtMember _value3;
//                private readonly JwtMember _value4;

//                public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
//                {
//                    _value1 = value1;
//                    _value2 = value2;
//                    _value3 = value3;
//                    _value4 = value4;
//                }

//                public int Count => 4;

//                public void Add(JwtMember value, out IMap map)
//                {
//                    if (value.Name == _value1.Name)
//                    {
//                        map = new FourElementMap(value, _value2, _value3, _value4);
//                    }
//                    else if (value.Name == _value2.Name)
//                    {
//                        map = new FourElementMap(_value1, value, _value3, _value4);
//                    }
//                    else if (value.Name == _value3.Name)
//                    {
//                        map = new FourElementMap(_value1, _value2, value, _value4);
//                    }
//                    else if (value.Name == _value4.Name)
//                    {
//                        map = new FourElementMap(_value1, _value2, _value3, value);
//                    }
//                    else
//                    {
//                        var multi = new MultiElementMap(5);
//                        multi.UnsafeStore(0, _value1);
//                        multi.UnsafeStore(1, _value2);
//                        multi.UnsafeStore(2, _value3);
//                        multi.UnsafeStore(3, _value4);
//                        multi.UnsafeStore(4, value);
//                        map = multi;
//                    }
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly FourElementMap _map;
//                    private int _counter;
//                    internal ObjectEnumerator(FourElementMap map)
//                    {
//                        _map = map;
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            if (_counter == 0)
//                            {
//                                return _map._value1;
//                            }
//                            else if (_counter == 1)
//                            {
//                                return _map._value2;
//                            }
//                            else if (_counter == 2)
//                            {
//                                return _map._value3;
//                            }
//                            else
//                            {
//                                return _map._value4;
//                            }
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _counter = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return _counter++ < 4;
//                    }
//                }
//            }

//            private sealed class MultiElementMap : IMap
//            {
//                private const int MaxMultiElements = 16;
//                private readonly JwtMember[] _keyValues;
//                private int _count;

//                public int Count => _count;

//                public MultiElementMap(int count)
//                {
//                    _keyValues = new JwtMember[MaxMultiElements];
//                    _count = count;
//                }

//                public void UnsafeStore(int index, JwtMember value)
//                {
//                    // TEST Debug.Assert(index < _keyValues.Length);
//                    _keyValues[index] = value;
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    for (int i = 0; i < _count; i++)
//                    {
//                        if (value.Name == _keyValues[i].Name)
//                        {
//                            // The key is in the map. 
//                            _keyValues[i] = value;
//                            map = this;
//                            return;
//                        }
//                    }

//                    if (_count < MaxMultiElements)
//                    {
//                        UnsafeStore(_count, value);
//                        _count++;
//                        map = this;
//                        return;
//                    }

//                    // Otherwise, upgrade to a many map.
//                    var many = new ManyElementMap(MaxMultiElements + 1);
//                    for (int i = 0; i < _count; i++)
//                    {
//                        JwtMember pair = _keyValues[i];
//                        many[pair.Name] = pair;
//                    }

//                    many[value.Name] = value;
//                    map = many;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return new ObjectEnumerator(this);
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();

//                /// <summary>
//                ///   An enumerable and enumerator for the properties of a JSON object.
//                /// </summary>
//                [DebuggerDisplay("{Current,nq}")]
//                public struct ObjectEnumerator : IEnumerator<JwtMember>
//                {
//                    private readonly MultiElementMap _map;
//                    private int _idx;
//                    internal ObjectEnumerator(MultiElementMap map)
//                    {
//                        _map = map;
//                        _idx = -1;
//                    }

//                    /// <inheritdoc />
//                    public JwtMember Current
//                    {
//                        get
//                        {
//                            return _map._keyValues[_idx];
//                        }
//                    }

//                    /// <inheritdoc />
//                    public void Dispose()
//                    {
//                    }

//                    /// <inheritdoc />
//                    public void Reset()
//                    {
//                        _idx = 0;
//                    }

//                    /// <inheritdoc />
//                    object IEnumerator.Current => Current;


//                    /// <inheritdoc />
//                    public bool MoveNext()
//                    {
//                        return ++_idx < _map.Count;
//                    }
//                }
//            }

//            private sealed class ManyElementMap : IMap
//            {
//                private readonly Dictionary<string, JwtMember> _dictionary;

//                public int Count => _dictionary.Count;

//                public ManyElementMap(int capacity)
//                {
//                    _dictionary = new Dictionary<string, JwtMember>(capacity);
//                }

//                public void Add(JwtMember value, out IMap map)
//                {
//                    map = this;
//                    _dictionary[value.Name] = value;
//                }

//                public JwtMember this[string key]
//                {
//                    get => _dictionary[key];
//                    set => _dictionary[key] = value;
//                }

//                public IEnumerator<JwtMember> GetEnumerator()
//                {
//                    return _dictionary.Values.GetEnumerator();
//                }

//                IEnumerator IEnumerable.GetEnumerator()
//                    => GetEnumerator();
//            }
//        }
//    }
//}
