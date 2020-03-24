// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON array.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtArray : IEnumerable<JwtValue>
    {
        private readonly List<JwtValue> _inner;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtArray"/> class.
        /// </summary>
        /// <param name="values"></param>
        public JwtArray(List<JwtValue> values)
        {
            _inner = values;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtArray"/> class.
        /// </summary>
        /// <param name="values"></param>
        public JwtArray(List<string> values)
        {
            var list = new List<JwtValue>(values.Count);
            for (int i = 0; i < values.Count; i++)
            {
                list.Add(new JwtValue(values[i]));
            }

            _inner = list;
        }

        /// <summary>
        /// Exports the <see cref="List{JwtValue}"/> use as back storage.
        /// </summary>
        /// <returns></returns>
        public List<JwtValue> ToList() => _inner;

        /// <summary>
        /// Gets the number of <see cref="JwtValue"/>s contained in the <see cref="JwtArray"/>.
        /// </summary>
        public int Count => _inner.Count;

        /// <summary>
        ///  Gets the <see cref="JwtValue"/> at the specified index.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public JwtValue this[int index] => _inner[index];

        /// <summary>
        /// Adds an <see cref="JwtValue"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(JwtValue value) => _inner.Add(value);

        /// <summary>
        /// Adds an <see cref="string"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(string value) => _inner.Add(new JwtValue(value));

        /// <summary>
        /// Adds an <see cref="bool"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(bool value) => _inner.Add(new JwtValue(value));

        /// <summary>
        /// Adds an <see cref="long"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(long value) => _inner.Add(new JwtValue(value));

        /// <summary>
        /// Adds an <see cref="JwtArray"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(JwtArray value) => _inner.Add(new JwtValue(value));

        /// <summary>
        /// Adds an <see cref="JwtObject"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(JwtObject value) => _inner.Add(new JwtValue(value));

        /// <summary>
        /// Adds an <see cref="double"/> to the end of the <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="value"></param>
        public void Add(double value) => _inner.Add(new JwtValue(value));

        internal void WriteTo(Utf8JsonWriter writer)
        {
            var inner = _inner;
            writer.WriteStartArray();
            for (int i = 0; i < inner.Count; i++)
            {
                inner[i].WriteTo(writer);
            }

            writer.WriteEndArray();
        }

        internal void WriteTo(Utf8JsonWriter writer, ReadOnlySpan<byte> utf8Name)
        {
            var inner = _inner;
            writer.WriteStartArray(utf8Name);
            for (int i = 0; i < inner.Count; i++)
            {
                inner[i].WriteTo(writer);
            }

            writer.WriteEndArray();
        }

        private string DebuggerDisplay()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <summary>
        /// Merge the <paramref name="other"/> into this <see cref="JwtArray"/>.
        /// </summary>
        /// <param name="other"></param>
        public void Merge(JwtArray other)
        {
            var srcProperties = other._inner;
            var dstProperties = _inner;
            for (int i = 0; i < srcProperties.Count; i++)
            {
                dstProperties.Add(srcProperties[i]);
            }
        }

        /// <inheritsdoc />
        public IEnumerator<JwtValue> GetEnumerator()
        {
            return ((IEnumerable<JwtValue>)_inner).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable<JwtValue>)_inner).GetEnumerator();
        }
    }
}