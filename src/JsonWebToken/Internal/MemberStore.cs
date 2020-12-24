// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Represents a store for JSON memebers.</summary>
    /// <remarks>Designed for progressive appending.</remarks>
    internal sealed class MemberStore : IEnumerable<JwtMember>
    {
        /// <summary>
        /// Creates a store that will grow its capacity from 0 item to a <see cref="Array"/> of 16 items.
        /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static MemberStore CreateFastGrowingStore()
            => new MemberStore(FastGrowingEmptyMap.Empty);

        /// <summary>
        /// Creates a store that will grow its capacity item by item until 4, 
        /// then to a <see cref="Array"/> of 16 items.
        /// Beyond 16 items, the implementation will switch to a <see cref="Dictionary{TKey, TValue}"/>.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static MemberStore CreateSlowGrowingStore()
            => new MemberStore(SlowGrowingEmptyMap.Empty);

        private IMap _map;

        /// <summary>
        /// Gets the count of elements.
        /// </summary>
        public int Count => _map.Count;

        private MemberStore(IMap map)
        {
            _map = map;
        }

        /// <summary>
        /// Writes in JSON the current <see cref="MemberStore"/> into the <paramref name="writer"/>>.
        /// </summary>
        /// <param name="writer"></param>
        public void WriteTo(Utf8JsonWriter writer)
            => _map.WriteTo(writer);

        /// <summary>
        /// Copy the current <see cref="MemberStore"/> into the <paramref name="destination"/>.
        /// </summary>
        /// <param name="destination"></param>
        public void CopyTo(MemberStore destination)
            => destination._map = _map.Merge(destination._map);

        /// <inheritdoc/>
        public IEnumerator<JwtMember> GetEnumerator()
            => _map.GetEnumerator();

        /// <summary>
        /// Adds the <paramref name="value"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public void Add(JwtMember value)
            => _map = _map.Add(value);

        /// <summary>
        /// Tries to get the <paramref name="value"/> with the <paramref name="key"/> as key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(JsonEncodedText key, [NotNullWhen(true)] out JwtMember value)
            => _map.TryGetValue(key, out value);

        /// <summary>
        /// Determines whether the current <see cref="MemberStore"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(JsonEncodedText key)
            => _map.ContainsKey(key);

        IEnumerator IEnumerable.GetEnumerator()
            => GetEnumerator();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void FastAdd(JwtMember value1, JwtMember value2)
            => _map = new TwoElementMap(value1, value2);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void FastAdd(JwtMember value1, JwtMember value2, JwtMember value3)
            => _map = new ThreeElementMap(value1, value2, value3);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void FastAdd(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
            => _map = new FourElementMap(value1, value2, value3, value4);

        internal void FastAdd(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4, JwtMember value5)
        {
            var map = new MultiElementMap(5);
            map.UnsafeStore(0, value1);
            map.UnsafeStore(1, value2);
            map.UnsafeStore(2, value3);
            map.UnsafeStore(3, value4);
            map.UnsafeStore(4, value5);
            _map = map;
        }

        internal void FastAdd(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4, JwtMember value5, JwtMember value6)
        {
            var map = new MultiElementMap(6);
            map.UnsafeStore(0, value1);
            map.UnsafeStore(1, value2);
            map.UnsafeStore(2, value3);
            map.UnsafeStore(3, value4);
            map.UnsafeStore(4, value5);
            map.UnsafeStore(5, value6);
            _map = map;
        }

        private interface IMap : IEnumerable<JwtMember>
        {
            public int Count { get; }

            public IMap Add(JwtMember value);

            public bool TryGetValue(JsonEncodedText key, [NotNullWhen(true)] out JwtMember value);

            public bool ContainsKey(JsonEncodedText key);

            void WriteTo(Utf8JsonWriter writer);

            IMap Merge(IMap map);
        }

        // Instance without any key/value pairs. Used as a singleton.
        private sealed class FastGrowingEmptyMap : IMap
        {
            public static readonly FastGrowingEmptyMap Empty = new FastGrowingEmptyMap();

            public int Count => 0;

            public IMap Add(JwtMember value)
            {
                // Create a new one-element map to store the key/value pair
                //map = new OneElementMap(value);
                var map = new MultiElementMap(1);
                map.UnsafeStore(0, value);
                return map;
            }

            public bool TryGetValue(JsonEncodedText key, [NotNullWhen(true)] out JwtMember value)
            {
                // Nothing here
                value = default;
                return false;
            }

            public bool ContainsKey(JsonEncodedText key)
                => false;

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return EmptyObjectEnumerator.Empty;
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
            {
            }

            public IMap Merge(IMap map)
            {
                return map;
            }
        }

        // Instance without any key/value pairs. Used as a singleton.
        private sealed class SlowGrowingEmptyMap : IMap
        {
            public static readonly SlowGrowingEmptyMap Empty = new SlowGrowingEmptyMap();

            public int Count => 0;

            public IMap Add(JwtMember value)
                => new OneElementMap(value);

            public bool TryGetValue(JsonEncodedText key, [NotNullWhen(true)] out JwtMember value)
            {
                // Nothing here
                value = default;
                return false;
            }

            public bool ContainsKey(JsonEncodedText key)
                => false;

            public IEnumerator<JwtMember> GetEnumerator()
                => EmptyObjectEnumerator.Empty;

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
            {
            }

            public IMap Merge(IMap map)
                => map;
        }

        /// <summary>
        ///   An enumerable and enumerator for the properties of a JSON object.
        /// </summary>
        [DebuggerDisplay("{Current,nq}")]
        private struct EmptyObjectEnumerator : IEnumerator<JwtMember>
        {
            public static readonly EmptyObjectEnumerator Empty = default;

            /// <inheritdoc />
            public JwtMember Current
                => default;

            /// <inheritdoc />
            public void Dispose()
            {
            }

            /// <inheritdoc />
            public void Reset()
            {
            }

            /// <inheritdoc />
            object IEnumerator.Current => Current;


            /// <inheritdoc />
            public bool MoveNext()
                => false;
        }

        private sealed class OneElementMap : IMap
        {
            private readonly JwtMember _value1;

            public OneElementMap(JwtMember value)
            {
                _value1 = value;
            }

            public int Count => 1;

            public IMap Add(JwtMember value)
                => new TwoElementMap(_value1, value);

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                if (key.Equals(_value1.Name))
                {
                    value = _value1;
                    return true;
                }
                else
                {
                    value = default;
                    return false;
                }
            }

            public bool ContainsKey(JsonEncodedText key)
                => key.Equals(_value1.Name);

            public IEnumerator<JwtMember> GetEnumerator()
                => new ObjectEnumerator(this);

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
                => _value1.WriteTo(writer);

            public IMap Merge(IMap map)
                => map.Add(_value1);

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMember>
            {
                private readonly OneElementMap _map;
                private bool _state;

                internal ObjectEnumerator(OneElementMap map)
                {
                    _map = map;
                    _state = true;
                }

                /// <inheritdoc />
                public JwtMember Current => _map._value1;

                /// <inheritdoc />
                public void Dispose()
                {
                }

                /// <inheritdoc />
                public void Reset()
                {
                }

                /// <inheritdoc />
                object IEnumerator.Current => Current;

                /// <inheritdoc />
                public bool MoveNext()
                {
                    bool state = _state;
                    _state = false;
                    return state;
                }
            }
        }

        private sealed class TwoElementMap : IMap
        {
            private readonly JwtMember _value1;
            private readonly JwtMember _value2;

            public TwoElementMap(JwtMember value1, JwtMember value2)
            {
                _value1 = value1;
                _value2 = value2;
            }

            public int Count => 2;

            public IMap Add(JwtMember value)
            {
                IMap map;
                if (value.Name.Equals(_value1.Name))
                {
                    map = new TwoElementMap(value, _value2);
                }
                else if (value.Name.Equals(_value2.Name))
                {
                    map = new TwoElementMap(_value1, value);
                }
                else
                {
                    map = new ThreeElementMap(_value1, _value2, value);
                }

                return map;
            }

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                if (key.Equals(_value1.Name))
                {
                    value = _value1;
                }
                else if (key.Equals(_value2.Name))
                {
                    value = _value2;
                }
                else
                {
                    value = default;
                    return false;
                }

                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
            }

            public bool ContainsKey(JsonEncodedText key)
                => key.Equals(_value1.Name) || key.Equals(_value2.Name);

            public IEnumerator<JwtMember> GetEnumerator()
                => new ObjectEnumerator(this);

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
                => map.Add(_value1)
                          .Add(_value2);

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMember>
            {
                private readonly TwoElementMap _map;
                private int _counter;
                internal ObjectEnumerator(TwoElementMap map)
                {
                    _map = map;
                    _counter = 0;
                }

                /// <inheritdoc />
                public JwtMember Current
                    => _counter == 0 ? _map._value1 : _map._value2;

                /// <inheritdoc />
                public void Dispose()
                {
                }

                /// <inheritdoc />
                public void Reset()
                {
                    _counter = 0;
                }

                /// <inheritdoc />
                object IEnumerator.Current => Current;


                /// <inheritdoc />
                public bool MoveNext()
                    => _counter++ < 2;
            }
        }

        private sealed class ThreeElementMap : IMap
        {
            private readonly JwtMember _value1;
            private readonly JwtMember _value2;
            private readonly JwtMember _value3;

            public ThreeElementMap(JwtMember value1, JwtMember value2, JwtMember value3)
            {
                _value1 = value1;
                _value2 = value2;
                _value3 = value3;
            }

            public int Count => 3;

            public IMap Add(JwtMember value)
            {
                IMap map;
                if (value.Name.Equals(_value1.Name))
                {
                    map = new ThreeElementMap(value, _value2, _value3);
                }
                else if (value.Name.Equals(_value2.Name))
                {
                    map = new ThreeElementMap(_value1, value, _value3);
                }
                else if (value.Name.Equals(_value3.Name))
                {
                    map = new ThreeElementMap(_value1, _value2, value);
                }
                else
                {
                    map = new FourElementMap(_value1, _value2, _value3, value);
                }

                return map;
            }

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                if (key.Equals(_value1.Name))
                {
                    value = _value1;
                }
                else if (key.Equals(_value2.Name))
                {
                    value = _value2;
                }
                else if (key.Equals(_value3.Name))
                {
                    value = _value3;
                }
                else
                {
                    value = default;
                    return false;
                }

                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
                _value3.WriteTo(writer);
            }

            public bool ContainsKey(JsonEncodedText key)
                => key.Equals(_value1.Name) || key.Equals(_value2.Name) || key.Equals(_value3.Name);

            public IEnumerator<JwtMember> GetEnumerator()
                => new ObjectEnumerator(this);

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
                => map.Add(_value1)
                      .Add(_value2)
                      .Add(_value3);

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMember>
            {
                private readonly ThreeElementMap _map;
                private int _counter;
                internal ObjectEnumerator(ThreeElementMap map)
                {
                    _map = map;
                    _counter = 0;
                }

                /// <inheritdoc />
                public JwtMember Current => _counter switch
                {
                    0 => _map._value1,
                    1 => _map._value2,
                    _ => _map._value3
                };

                /// <inheritdoc />
                public void Dispose()
                {
                }

                /// <inheritdoc />
                public void Reset()
                {
                    _counter = 0;
                }

                /// <inheritdoc />
                object IEnumerator.Current => Current;


                /// <inheritdoc />
                public bool MoveNext()
                    => _counter++ < 3;
            }
        }

        private sealed class FourElementMap : IMap
        {
            private readonly JwtMember _value1;
            private readonly JwtMember _value2;
            private readonly JwtMember _value3;
            private readonly JwtMember _value4;

            public FourElementMap(JwtMember value1, JwtMember value2, JwtMember value3, JwtMember value4)
            {
                _value1 = value1;
                _value2 = value2;
                _value3 = value3;
                _value4 = value4;
            }

            public int Count => 4;

            public IMap Add(JwtMember value)
            {
                IMap map;
                if (value.Name.Equals(_value1.Name))
                {
                    map = new FourElementMap(value, _value2, _value3, _value4);
                }
                else if (value.Name.Equals(_value2.Name))
                {
                    map = new FourElementMap(_value1, value, _value3, _value4);
                }
                else if (value.Name.Equals(_value3.Name))
                {
                    map = new FourElementMap(_value1, _value2, value, _value4);
                }
                else if (value.Name.Equals(_value4.Name))
                {
                    map = new FourElementMap(_value1, _value2, _value3, value);
                }
                else
                {
                    var multi = new MultiElementMap(5);
                    multi.UnsafeStore(0, _value1);
                    multi.UnsafeStore(1, _value2);
                    multi.UnsafeStore(2, _value3);
                    multi.UnsafeStore(3, _value4);
                    multi.UnsafeStore(4, value);
                    map = multi;
                }

                return map;
            }

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                if (key.Equals(_value1.Name))
                {
                    value = _value1;
                }
                else if (key.Equals(_value2.Name))
                {
                    value = _value2;
                }
                else if (key.Equals(_value3.Name))
                {
                    value = _value3;
                }
                else if (key.Equals(_value4.Name))
                {
                    value = _value4;
                }
                else
                {
                    value = default;
                    return false;
                }

                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
                _value3.WriteTo(writer);
                _value4.WriteTo(writer);
            }

            public bool ContainsKey(JsonEncodedText key)
                => key.Equals(_value1.Name) || key.Equals(_value2.Name) || key.Equals(_value3.Name) || key.Equals(_value4.Name);

            public IEnumerator<JwtMember> GetEnumerator()
                => new ObjectEnumerator(this);

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
                => map.Add(_value1)
                      .Add(_value2)
                      .Add(_value3)
                      .Add(_value4);

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMember>
            {
                private readonly FourElementMap _map;
                private int _counter;
                internal ObjectEnumerator(FourElementMap map)
                {
                    _map = map;
                    _counter = 0;
                }

                /// <inheritdoc />
                public JwtMember Current
                    => _counter switch
                    {
                        0 => _map._value1,
                        1 => _map._value2,
                        2 => _map._value3,
                        _ => _map._value4
                    };

                /// <inheritdoc />
                public void Dispose()
                {
                }

                /// <inheritdoc />
                public void Reset()
                {
                    _counter = 0;
                }

                /// <inheritdoc />
                object IEnumerator.Current => Current;


                /// <inheritdoc />
                public bool MoveNext()
                {
                    return _counter++ < 4;
                }
            }
        }

        private sealed class MultiElementMap : IMap
        {
            private const int MaxMultiElements = 16;
            private readonly JwtMember[] _keyValues;
            private int _count;

            public int Count => _count;

            public MultiElementMap(int count)
            {
                _keyValues = new JwtMember[MaxMultiElements];
                _count = count;
            }

            public void UnsafeStore(int index, JwtMember value)
            {
                Debug.Assert(index < _keyValues.Length);
                _keyValues[index] = value;
            }

            public IMap Add(JwtMember value)
            {
                if (_count < MaxMultiElements)
                {
                    for (int i = 0; i < _count; i++)
                    {
                        if (value.Name.Equals(_keyValues[i].Name))
                        {
                            _keyValues[i] = value;
                            goto Added;
                        }
                    }

                    UnsafeStore(_count, value);
                    _count++;
                Added:
                    return this;
                }

                // Otherwise, upgrade to a many map.
                var many = new ManyElementMap(MaxMultiElements + 1);
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    many[pair.Name] = pair;
                }

                many[value.Name] = value;
                return many;
            }

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    if (key.Equals(pair.Name))
                    {
                        value = pair;
                        return true;
                    }
                }

                value = default;
                return false;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    pair.WriteTo(writer);
                }
            }

            public bool ContainsKey(JsonEncodedText key)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    if (key.Equals(pair.Name))
                    {
                        return true;
                    }
                }

                return false;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember item = _keyValues[i];
                    map = map.Add(item);
                }

                return map;
            }

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMember>
            {
                private readonly MultiElementMap _map;
                private int _idx;
                internal ObjectEnumerator(MultiElementMap map)
                {
                    _map = map;
                    _idx = -1;
                }

                /// <inheritdoc />
                public JwtMember Current
                    => _map._keyValues[_idx];

                /// <inheritdoc />
                public void Dispose()
                {
                }

                /// <inheritdoc />
                public void Reset()
                {
                    _idx = 0;
                }

                /// <inheritdoc />
                object IEnumerator.Current => Current;


                /// <inheritdoc />
                public bool MoveNext()
                    => ++_idx < _map.Count;
            }
        }

        private sealed class ManyElementMap : IMap
        {
            private readonly Dictionary<JsonEncodedText, JwtMember> _dictionary;

            public int Count => _dictionary.Count;

            public ManyElementMap(int capacity)
            {
                _dictionary = new Dictionary<JsonEncodedText, JwtMember>(capacity);
            }

            public IMap Add(JwtMember value)
            {
                _dictionary[value.Name] = value;
                return this;
            }

            public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            {
                var result = _dictionary.TryGetValue(key, out var tmp);
                value = tmp;
                return result;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                foreach (KeyValuePair<JsonEncodedText, JwtMember> pair in _dictionary)
                {
                    pair.Value.WriteTo(writer);
                }
            }

            public bool ContainsKey(JsonEncodedText key)
                => _dictionary.ContainsKey(key);

            public JwtMember this[JsonEncodedText key]
            {
                get => _dictionary[key];
                set => _dictionary[key] = value;
            }

            public IEnumerator<JwtMember> GetEnumerator()
                => _dictionary.Values.GetEnumerator();

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                foreach (var item in _dictionary.Values)
                {
                    map = map.Add(item);
                }

                return map;
            }
        }
    }
}