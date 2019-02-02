// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public class JwtObject
    {
        private readonly List<JwtProperty> _properties = new List<JwtProperty>();

        public int Count => _properties.Count;

        public void Add(JwtProperty property)
        {
            _properties.Add(property);
        }

        public JwtProperty this[int index] => _properties[index];

        public JwtProperty this[ReadOnlyMemory<byte> key]
        {
            get
            {
                var span = key.Span;
                for (int i = 0; i < _properties.Count; i++)
                {
                    var current = _properties[i];
                    if (current.Utf8Name.Span.SequenceEqual(span))
                    {
                        return current;
                    }
                }

                return default;
            }

            set
            {
                var spanValue = value.Utf8Name.Span;
                for (int i = 0; i < _properties.Count; i++)
                {
                    var current = _properties[i];
                    if (current.Utf8Name.Span.SequenceEqual(spanValue))
                    {
                        _properties[i] = value;
                    }
                }

                _properties.Add(value);
            }
        }

        public bool TryGetValue(string key, out JwtProperty value)
        {
            return TryGetValue(Encoding.UTF8.GetBytes(key), out value);
        }

        public bool TryGetValue(ReadOnlyMemory<byte> key, out JwtProperty value)
        {
            var span = key.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Utf8Name.Span.SequenceEqual(span))
                {
                    value = current;
                    return true;
                }
            }

            value = default;
            return false;
        }

        public bool ContainsKey(ReadOnlyMemory<byte> key)
        {
            var span = key.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Utf8Name.Span.SequenceEqual(span))
                {
                    return true;
                }
            }

            return false;
        }

        public void Replace(JwtProperty property)
        {
            var span = property.Utf8Name.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Utf8Name.Span.SequenceEqual(span))
                {
                    _properties.RemoveAt(i);
                    break;
                }
            }

            _properties.Add(property);
        }


        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            for (int i = 0; i < _properties.Count; i++)
            {
                _properties[i].WriteTo(ref writer);
            }

            writer.WriteEndObject();
        }

        internal void WriteTo(ref Utf8JsonWriter writer, ReadOnlySpan<byte> utf8Name)
        {
            writer.WriteStartObject(utf8Name);
            for (int i = 0; i < _properties.Count; i++)
            {
                _properties[i].WriteTo(ref writer);
            }

            writer.WriteEndObject();
        }

        private string DebuggerDisplay()
        {
            var bufferWriter = new BufferWriter();
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                WriteTo(ref writer);
                writer.Flush();

                var input = bufferWriter.GetSequence();
                if (input.IsSingleSegment)
                {
                    return Encoding.UTF8.GetString(input.First.Span.ToArray());
                }
                else
                {
                    var encodedBytes = new byte[(int)input.Length];

                    input.CopyTo(encodedBytes);
                    return Encoding.UTF8.GetString(encodedBytes);
                }
            }
        }
    }
}