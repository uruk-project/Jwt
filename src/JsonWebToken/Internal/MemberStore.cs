// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    internal sealed class MemberStore : IEnumerable<JwtMember>
    {
        public static MemberStore CreateForPayload()
            => new MemberStore(EmptyMapForPayload.Empty);

        public static MemberStore CreateForHeader()
            => new MemberStore(EmptyMapForHeader.Empty);

        private IMap _map;

        /// <summary>
        /// Gets the count of elements.
        /// </summary>
        public int Count => _map.Count;

        private MemberStore(IMap map)
        {
            _map = map;
        }

        public void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            _map.WriteTo(writer);
            writer.WriteEndObject();
        }

        public void CopyTo(MemberStore destination)
        {
            destination._map = _map.Merge(destination._map);
        }

        public IEnumerator<JwtMember> GetEnumerator()
        {
            return _map.GetEnumerator();
        }

        /// <summary>
        /// Tries to add the <paramref name="value"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryAdd(JwtMember value)
            => _map.TryAdd(value, out _map);

        /// <summary>
        /// Tries to get the <paramref name="value"/> with the <paramref name="key"/> as key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMember value)
            => _map.TryGetValue(key, out value);

        /// <summary>
        /// Determines whether the current <see cref="MemberStore"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
            => _map.ContainsKey(key);

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }

        private interface IMap : IEnumerable<JwtMember>
        {
            public int Count { get; }

            public bool TryAdd(JwtMember value, out IMap map);

            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMember value);

            public bool ContainsKey(string key);

            void WriteTo(Utf8JsonWriter writer);

            IMap Merge(IMap map);
        }

        // Instance without any key/value pairs. Used as a singleton.
        private sealed class EmptyMapForPayload : IMap
        {
            public static readonly EmptyMapForPayload Empty = new EmptyMapForPayload();

            public int Count => 0;

            public bool TryAdd(JwtMember value, out IMap map)
            {
                // Create a new one-element map to store the key/value pair
                //map = new OneElementMap(value);
                var newMap = new MultiElementMap(1);
                newMap.UnsafeStore(0, value);
                map = newMap;
                return true;
            }

            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMember value)
            {
                // Nothing here
                value = default;
                return false;
            }

            public bool ContainsKey(string key)
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
        private sealed class EmptyMapForHeader : IMap
        {
            public static readonly EmptyMapForPayload Empty = new EmptyMapForPayload();

            public int Count => 0;

            public bool TryAdd(JwtMember value, out IMap map)
            {
                // Create a new one-element map to store the key/value pair
                map = new OneElementMap(value);
                return true;
            }

            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMember value)
            {
                // Nothing here
                value = default;
                return false;
            }

            public bool ContainsKey(string key)
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

            public bool TryAdd(JwtMember value, out IMap map)
            {
                if (value.Name == _value1.Name)
                {
                    map = new OneElementMap(value);
                }
                else
                {
                    map = new TwoElementMap(_value1, value);
                }

                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                if (key == _value1.Name)
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

            public bool ContainsKey(string key)
            {
                return key == _value1.Name;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
            }

            public IMap Merge(IMap map)
            {
                map.TryAdd(_value1, out map);
                return map;
            }

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
                public JwtMember Current
                {
                    get
                    {
                        return _map._value1;
                    }
                }

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

            public bool TryAdd(JwtMember value, out IMap map)
            {
                if (value.Name == _value1.Name)
                {
                    map = new TwoElementMap(value, _value2);
                }
                else if (value.Name == _value2.Name)
                {
                    map = new TwoElementMap(_value1, value);
                }
                else
                {
                    map = new ThreeElementMap(_value1, _value2, value);
                }

                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                if (key == _value1.Name)
                {
                    value = _value1;
                    goto Found;
                }
                if (key == _value2.Name)
                {
                    value = _value2;
                    goto Found;
                }
                else
                {
                    value = default;
                    return false;
                }

            Found:
                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
            }

            public bool ContainsKey(string key)
            {
                return key == _value1.Name || key == _value2.Name;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                map.TryAdd(_value1, out map);
                map.TryAdd(_value2, out map);
                return map;
            }

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
                {
                    get
                    {
                        if (_counter == 0)
                        {
                            return _map._value1;
                        }
                        else
                        {
                            return _map._value2;
                        }
                    }
                }

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
                    return _counter++ < 2;
                }
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

            public bool TryAdd(JwtMember value, out IMap map)
            {
                if (value.Name == _value1.Name)
                {
                    map = new ThreeElementMap(value, _value2, _value3);
                }
                else if (value.Name == _value2.Name)
                {
                    map = new ThreeElementMap(_value1, value, _value3);
                }
                else if (value.Name == _value3.Name)
                {
                    map = new ThreeElementMap(_value1, _value2, value);
                }
                else
                {
                    map = new FourElementMap(_value1, _value2, _value3, value);
                }

                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                if (key == _value1.Name)
                {
                    value = _value1;
                    goto Found;
                }
                if (key == _value2.Name)
                {
                    value = _value2;
                    goto Found;
                }
                if (key == _value3.Name)
                {
                    value = _value3;
                    goto Found;
                }
                else
                {
                    value = default;
                    return false;
                }

            Found:
                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
                _value3.WriteTo(writer);
            }

            public bool ContainsKey(string key)
            {
                return key == _value1.Name || key == _value2.Name || key == _value3.Name;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                map.TryAdd(_value1, out map);
                map.TryAdd(_value2, out map);
                map.TryAdd(_value3, out map);
                return map;
            }

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
                public JwtMember Current
                {
                    get
                    {
                        if (_counter == 0)
                        {
                            return _map._value1;
                        }
                        else if (_counter == 1)
                        {
                            return _map._value2;
                        }
                        else
                        {
                            return _map._value3;
                        }
                    }
                }

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
                    return _counter++ < 3;
                }
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

            public bool TryAdd(JwtMember value, out IMap map)
            {
                if (value.Name == _value1.Name)
                {
                    map = new FourElementMap(value, _value2, _value3, _value4);
                }
                else if (value.Name == _value2.Name)
                {
                    map = new FourElementMap(_value1, value, _value3, _value4);
                }
                else if (value.Name == _value3.Name)
                {
                    map = new FourElementMap(_value1, _value2, value, _value4);
                }
                else if (value.Name == _value4.Name)
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

                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                if (key == _value1.Name)
                {
                    value = _value1;
                    goto Found;
                }
                if (key == _value2.Name)
                {
                    value = _value2;
                    goto Found;
                }
                else if (key == _value3.Name)
                {
                    value = _value3;
                    goto Found;
                }
                else if (key == _value4.Name)
                {
                    value = _value4;
                    goto Found;
                }
                else
                {
                    value = default;
                    return false;
                }

            Found:
                return true;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
                _value2.WriteTo(writer);
                _value3.WriteTo(writer);
                _value4.WriteTo(writer);
            }

            public bool ContainsKey(string key)
            {
                return key == _value1.Name || key == _value2.Name || key == _value3.Name || key == _value4.Name;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                map.TryAdd(_value1, out map);
                map.TryAdd(_value2, out map);
                map.TryAdd(_value3, out map);
                map.TryAdd(_value4, out map);
                return map;
            }

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
                {
                    get
                    {
                        if (_counter == 0)
                        {
                            return _map._value1;
                        }
                        else if (_counter == 1)
                        {
                            return _map._value2;
                        }
                        else if (_counter == 2)
                        {
                            return _map._value3;
                        }
                        else
                        {
                            return _map._value4;
                        }
                    }
                }

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

            public bool TryAdd(JwtMember value, out IMap map)
            {
                for (int i = 0; i < _count; i++)
                {
                    if (value.Name == _keyValues[i].Name)
                    {
                        // The key is in the map. 
                        _keyValues[i] = value;
                        map = this;
                        goto Exit;
                    }
                }

                if (_count < MaxMultiElements)
                {
                    UnsafeStore(_count, value);
                    _count++;
                    map = this;
                    goto Exit;
                }

                // Otherwise, upgrade to a many map.
                var many = new ManyElementMap(MaxMultiElements + 1);
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    many[pair.Name] = pair;
                }

                many[value.Name] = value;
                map = many;

            Exit:
                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    if (key == pair.Name)
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

            public bool ContainsKey(string key)
            {
                for (int i = 0; i < _count; i++)
                {
                    JwtMember pair = _keyValues[i];
                    if (key == pair.Name)
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
                    map.TryAdd(item, out map);
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
                {
                    get
                    {
                        return _map._keyValues[_idx];
                    }
                }

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
                {
                    return ++_idx < _map.Count;
                }
            }
        }

        private sealed class ManyElementMap : IMap
        {
            private readonly Dictionary<string, JwtMember> _dictionary;

            public int Count => _dictionary.Count;

            public ManyElementMap(int capacity)
            {
                _dictionary = new Dictionary<string, JwtMember>(capacity);
            }

            public bool TryAdd(JwtMember value, out IMap map)
            {
                map = this;
                _dictionary[value.Name] = value;

                return true;
            }

            public bool TryGetValue(string key, out JwtMember value)
            {
                var result = _dictionary.TryGetValue(key, out var tmp);
                value = tmp;
                return result;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                foreach (KeyValuePair<string, JwtMember> pair in _dictionary)
                {
                    pair.Value.WriteTo(writer);
                }
            }

            public bool ContainsKey(string key)
            {
                return _dictionary.ContainsKey(key);
            }

            public JwtMember this[string key]
            {
                get => _dictionary[key];
                set => _dictionary[key] = value;
            }

            public IEnumerator<JwtMember> GetEnumerator()
            {
                return _dictionary.Values.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public IMap Merge(IMap map)
            {
                foreach (var item in _dictionary.Values)
                {
                    map.TryAdd(item, out map);
                }

                return map;
            }

            ///// <summary>
            /////   An enumerable and enumerator for the properties of a JSON object.
            ///// </summary>
            //[DebuggerDisplay("{Current,nq}")]
            //public struct ObjectEnumerator : IEnumerator<KeyValuePair<string, JwtValueX>>
            //{
            //    private readonly ManyElementMap _map;
            //    private int _idx;
            //    internal ObjectEnumerator(ManyElementMap map)
            //    {
            //        _map = map;
            //        _idx = 0;
            //    }

            //    /// <inheritdoc />
            //    public KeyValuePair<string, JwtValueX> Current
            //    {
            //        get
            //        {
            //            return _map._dictionary.[_idx];
            //        }
            //    }

            //    /// <inheritdoc />
            //    public void Dispose()
            //    {
            //    }

            //    /// <inheritdoc />
            //    public void Reset()
            //    {
            //        _idx = 0;
            //    }

            //    /// <inheritdoc />
            //    object IEnumerator.Current => Current;


            //    /// <inheritdoc />
            //    public bool MoveNext()
            //    {
            //        return _idx++ >= _map.Count;
            //    }
            //}
        }
    }
}