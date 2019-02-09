// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON array.s
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtArray
    {
        private readonly List<JwtValue> _inner;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtArray"/> class.
        /// </summary>
        /// <param name="values"></param>
        public JwtArray(List<JwtValue> values)
        {
            _inner = new List<JwtValue>(values);
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

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            writer.WriteStartArray();
            for (int i = 0; i < _inner.Count; i++)
            {
                _inner[i].WriteTo(ref writer);
            }

            writer.WriteEndArray();
        }

        internal void WriteTo(ref Utf8JsonWriter writer, ReadOnlySpan<byte> utf8Name)
        {
            writer.WriteStartArray(utf8Name);
            for (int i = 0; i < _inner.Count; i++)
            {
                _inner[i].WriteTo(ref writer);
            }

            writer.WriteEndArray();
        }

        private string DebuggerDisplay()
        {
            var bufferWriter = new BufferWriter();
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                WriteTo(ref writer);
                writer.Flush();

                var input = bufferWriter.OutputAsSequence;
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