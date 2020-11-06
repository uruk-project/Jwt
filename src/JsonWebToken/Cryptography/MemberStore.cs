// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace JsonWebToken.Internal
{
    internal sealed class MemberStore : IEnumerable<JwtMemberX>
    {
        private Map _map = EmptyMap.Empty;

        /// <summary>
        /// Gets the count of elements.
        /// </summary>
        public int Count => _map.Count;

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

        public IEnumerator<JwtMemberX> GetEnumerator()
        {
            return _map.GetEnumerator();
        }

        /// <summary>
        /// Tries to add the <paramref name="value"/>.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryAdd(JwtMemberX value)
            => _map.TryAdd(value, out _map);

        /// <summary>
        /// Tries to get the <paramref name="value"/> with the <paramref name="key"/> as key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMemberX value)
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

        private interface Map : IEnumerable<JwtMemberX>
        {
            public int Count { get; }

            public bool TryAdd(JwtMemberX value, out Map map);

            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMemberX value);

            public bool ContainsKey(string key);

            void WriteTo(Utf8JsonWriter writer);

            Map Merge(Map map);
        }

        // Instance without any key/value pairs. Used as a singleton.
        private sealed class EmptyMap : Map
        {
            public static readonly EmptyMap Empty = new EmptyMap();

            public int Count => 0;

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                // Create a new one-element map to store the key/value pair
                map = new OneElementMap(value);
                return true;
            }

            public bool TryGetValue(string key, [NotNullWhen(true)] out JwtMemberX value)
            {
                // Nothing here
                value = default;
                return false;
            }

            public bool ContainsKey(string key)
                => false;

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
            {
            }

            public Map Merge(Map map)
            {
                return map;
            }

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMemberX>
            {
                private readonly EmptyMap _map;

                internal ObjectEnumerator(EmptyMap map)
                {
                    _map = map;
                }

                /// <inheritdoc />
                public JwtMemberX Current
                {
                    get
                    {
                        return default;
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
                    return false;
                }
            }
        }

        private sealed class OneElementMap : Map
        {
            private readonly JwtMemberX _value1;

            public OneElementMap(JwtMemberX value)
            {
                _value1 = value;
            }

            public int Count => 1;

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                if (value.Name == _value1.Name)
                {
                    map = this;
                    return false;
                }
                else
                {
                    map = new TwoElementMap(_value1, value);
                    return true;
                }
            }

            public bool TryGetValue(string key, out JwtMemberX value)
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

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public void WriteTo(Utf8JsonWriter writer)
            {
                _value1.WriteTo(writer);
            }

            public Map Merge(Map map)
            {
                map.TryAdd(_value1, out map);
                return map;
            }

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMemberX>
            {
                private readonly OneElementMap _map;
                private bool _state;

                internal ObjectEnumerator(OneElementMap map)
                {
                    _map = map;
                    _state = true;
                }

                /// <inheritdoc />
                public JwtMemberX Current
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

        private sealed class TwoElementMap : Map
        {
            private readonly JwtMemberX _value1;
            private readonly JwtMemberX _value2;

            public TwoElementMap(JwtMemberX value1, JwtMemberX value2)
            {
                _value1 = value1;
                _value2 = value2;
            }

            public int Count => 2;

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                if (value.Name == _value1.Name || value.Name == _value2.Name)
                {
                    map = this;
                    return true;
                }
                else
                {
                    map = new ThreeElementMap(_value1, _value2, value);
                    return true;
                }
            }

            public bool TryGetValue(string key, out JwtMemberX value)
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

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public Map Merge(Map map)
            {
                map.TryAdd(_value1, out map);
                map.TryAdd(_value2, out map);
                return map;
            }

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMemberX>
            {
                private readonly TwoElementMap _map;
                private int _counter;
                internal ObjectEnumerator(TwoElementMap map)
                {
                    _map = map;
                    _counter = 0;
                }

                /// <inheritdoc />
                public JwtMemberX Current
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

        private sealed class ThreeElementMap : Map
        {
            private readonly JwtMemberX _value1;
            private readonly JwtMemberX _value2;
            private readonly JwtMemberX _value3;

            public ThreeElementMap(JwtMemberX value1, JwtMemberX value2, JwtMemberX value3)
            {
                _value1 = value1;
                _value2 = value2;
                _value3 = value3;
            }

            public int Count => 3;

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                if (value.Name == _value1.Name || value.Name == _value2.Name || value.Name == _value3.Name)
                {
                    map = this;
                    return false;
                }
                else
                {
                    var multi = new MultiElementMap(4);
                    multi.UnsafeStore(0, _value1);
                    multi.UnsafeStore(1, _value2);
                    multi.UnsafeStore(2, _value3);
                    multi.UnsafeStore(3, value);
                    map = multi;
                    return true;
                }
            }

            public bool TryGetValue(string key, out JwtMemberX value)
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

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public Map Merge(Map map)
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
            public struct ObjectEnumerator : IEnumerator<JwtMemberX>
            {
                private readonly ThreeElementMap _map;
                private int _counter;
                internal ObjectEnumerator(ThreeElementMap map)
                {
                    _map = map;
                    _counter = 0;
                }

                /// <inheritdoc />
                public JwtMemberX Current
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

        private sealed class MultiElementMap : Map
        {
            private const int MaxMultiElements = 16;
            private readonly JwtMemberX[] _keyValues;

            public int Count => _keyValues.Length;

            public MultiElementMap(int count)
            {
                Debug.Assert(count <= MaxMultiElements);
                _keyValues = new JwtMemberX[count];
            }

            public void UnsafeStore(int index, JwtMemberX value)
            {
                Debug.Assert(index < _keyValues.Length);
                _keyValues[index] = value;
            }

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                for (int i = 0; i < _keyValues.Length; i++)
                {
                    if (value.Name == _keyValues[i].Name)
                    {
                        // The key is in the map. 
                        map = this;
                        return false;
                    }
                }

                // The key does not already exist in this map.
                // We need to create a new map that has the additional key/value pair.
                // If with the addition we can still fit in a multi map, create one.
                if (_keyValues.Length < MaxMultiElements)
                {
                    var multi = new MultiElementMap(_keyValues.Length + 1);
                    Array.Copy(_keyValues, 0, multi._keyValues, 0, _keyValues.Length);
                    multi._keyValues[_keyValues.Length] = value;
                    map = multi;
                    return true;
                }

                // Otherwise, upgrade to a many map.
                var many = new ManyElementMap(MaxMultiElements + 1);
                foreach (JwtMemberX pair in _keyValues)
                {
                    many[pair.Name] = pair;
                }

                many[value.Name] = value;
                map = many;
                return true;
            }

            public bool TryGetValue(string key, out JwtMemberX value)
            {
                foreach (JwtMemberX pair in _keyValues)
                {
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
                foreach (JwtMemberX pair in _keyValues)
                {
                    pair.WriteTo(writer);
                }
            }

            public bool ContainsKey(string key)
            {
                foreach (JwtMemberX pair in _keyValues)
                {
                    if (key == pair.Name)
                    {
                        return true;
                    }
                }

                return false;
            }

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return new ObjectEnumerator(this);
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public Map Merge(Map map)
            {
                foreach (var item in _keyValues)
                {
                    map.TryAdd(item, out map);
                }

                return map;
            }

            /// <summary>
            ///   An enumerable and enumerator for the properties of a JSON object.
            /// </summary>
            [DebuggerDisplay("{Current,nq}")]
            public struct ObjectEnumerator : IEnumerator<JwtMemberX>
            {
                private readonly MultiElementMap _map;
                private int _idx;
                internal ObjectEnumerator(MultiElementMap map)
                {
                    _map = map;
                    _idx = -1;
                }

                /// <inheritdoc />
                public JwtMemberX Current
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

        private sealed class ManyElementMap : Map
        {
            private readonly Dictionary<string, JwtMemberX> _dictionary;

            public int Count => _dictionary.Count;

            public ManyElementMap(int capacity)
            {
                _dictionary = new Dictionary<string, JwtMemberX>(capacity);
            }

            public bool TryAdd(JwtMemberX value, out Map map)
            {
                map = this;
#if NETCOREAPP
                return _dictionary.TryAdd(value.Name, value);
#else
                if (_dictionary.ContainsKey(value.Name))
                {
                    return false;
                }
                else
                {
                    _dictionary[value.Name] = value;
                    return true;
                }
#endif
            }

            public bool TryGetValue(string key, out JwtMemberX value)
            {
                var result = _dictionary.TryGetValue(key, out var tmp);
                value = tmp;
                return result;
            }

            public void WriteTo(Utf8JsonWriter writer)
            {
                foreach (KeyValuePair<string, JwtMemberX> pair in _dictionary)
                {
                    pair.Value.WriteTo(writer);
                }
            }

            public bool ContainsKey(string key)
            {
                return _dictionary.ContainsKey(key);
            }

            public JwtMemberX this[string key]
            {
                get => _dictionary[key];
                set => _dictionary[key] = value;
            }

            public IEnumerator<JwtMemberX> GetEnumerator()
            {
                return _dictionary.Values.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
                => GetEnumerator();

            public Map Merge(Map map)
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