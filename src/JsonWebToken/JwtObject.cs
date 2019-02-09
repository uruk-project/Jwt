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
    /// <summary>
    /// Represents a JSON object.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public class JwtObject
    {
        private readonly List<JwtProperty> _properties = new List<JwtProperty>(6);

        /// <summary>
        /// Gets the number of <see cref="JwtProperty"/>.
        /// </summary>
        public int Count => _properties.Count;

        /// <summary>
        /// Adds a <see cref="JwtProperty"/> to the end of the <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="property"></param>
        public void Add(JwtProperty property)
        {
            _properties.Add(property);
        }

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> at the specified index;
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public JwtProperty this[int index] => _properties[index];

        /// <summary>
        /// Gets or sets the <see cref="JwtProperty"/> at the specified key;
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtProperty this[string key] => this[Encoding.UTF8.GetBytes(key)];

        /// <summary>
        /// Gets or sets the <see cref="JwtProperty"/> at the specified key;
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(string key, out JwtProperty value)
        {
            return TryGetValue(Encoding.UTF8.GetBytes(key), out value);
        }

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Determines whether a <see cref="JwtProperty"/> is in the <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Determines whether a <see cref="JwtProperty"/> is in the <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key) => ContainsKey(Encoding.UTF8.GetBytes(key));

        /// <summary>
        /// Replaces a <see cref="JwtProperty"/> 
        /// </summary>
        /// <param name="property"></param>
        public void Replace(JwtProperty property)
        {
            var span = property.Utf8Name.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Utf8Name.Span.SequenceEqual(span))
                {
                    _properties[i] = property;
                    break;
                }
            }

            throw new InvalidOperationException();
        }

        /// <summary>
        /// Serializes the <see cref="JwtObject"/> into it JSON representation.
        /// </summary>
        /// <returns></returns>
        public byte[] Serialize()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Serialize(bufferWriter);
                return bufferWriter.WrittenSpan.ToArray();
            }
        }

        /// <summary>
        /// Serializes the <see cref="JwtObject"/> into it JSON representation.
        /// </summary>
        /// <param name="bufferWriter"></param>
        public void Serialize(IBufferWriter<byte> bufferWriter)
        {
            Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = false, SkipValidation = true }));
            WriteTo(ref writer);
            writer.Flush();
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
            return ToString();
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                WriteTo(ref writer);
                writer.Flush();

                var input = bufferWriter.WrittenSpan;
                return Encoding.UTF8.GetString(input.ToArray());
            }
        }
    }
}