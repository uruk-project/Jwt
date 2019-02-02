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
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtArray
    {
        private readonly List<JwtValue> _inner;

        public JwtArray(List<JwtValue> values)
        {
            _inner = new List<JwtValue>(values);
        }

        public JwtArray(List<string> values)
        {
            var list = new List<JwtValue>(values.Count);
            for (int i = 0; i < values.Count; i++)
            {
                list.Add(new JwtValue(values[i]));
            }

            _inner = list;
        }

        public List<JwtValue> ToList() => _inner;

        public int Count => _inner.Count;

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