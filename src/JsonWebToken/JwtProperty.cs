﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON property.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtProperty
    {
        /// <summary>
        /// Gets whether the <see cref="JwtProperty"/> is empty.
        /// </summary>
        public bool IsEmpty => Utf8Name.IsEmpty;

        /// <summary>
        /// Gets the <see cref="JwtTokenType"/> of the <see cref="JwtProperty"/>.
        /// </summary>
        public readonly JwtTokenType Type;

        /// <summary>
        /// Gets the name of the <see cref="JwtProperty"/> in its UTF-8 representation.
        /// </summary>
        public readonly ReadOnlyMemory<byte> Utf8Name;

        /// <summary>
        /// Gets the value of the <see cref="JwtProperty"/>.
        /// </summary>
        public readonly object Value;

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, JwtArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, JwtObject value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.Object;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, string value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.String;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, byte[] value)
        {
            Type = JwtTokenType.Utf8String;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, long value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, int value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, double value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, float value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name, bool value)
        {
            Type = JwtTokenType.Boolean;
            Utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="utf8Name"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name)
        {
            Type = JwtTokenType.Null;
            Utf8Name = utf8Name.ToArray();
            Value = null;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JwtArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JwtObject value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.Object;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, string value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.String;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, byte[] value)
        {
            Type = JwtTokenType.Utf8String;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, long value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, int value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, double value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, float value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name, bool value)
        {
            Type = JwtTokenType.Boolean;
            Utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="utf8Name"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name)
        {
            Type = JwtTokenType.Null;
            Utf8Name = utf8Name;
            Value = null;
        }


        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, JwtArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, JwtObject value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.Object;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, string value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.String;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, byte[] value)
        {
            Type = JwtTokenType.Utf8String;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, long value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, int value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, double value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, float value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtProperty(string name, bool value)
        {
            Type = JwtTokenType.Boolean;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="name"></param>
        public JwtProperty(string name)
        {
            Type = JwtTokenType.Null;
            Utf8Name = Encoding.UTF8.GetBytes(name);
            Value = null;
        }


        /// <summary>
        /// Gets or sets the <see cref="JwtProperty"/> at the specified key;
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtProperty this[string key]
        {
            get
            {
                if (Type == JwtTokenType.Object && ((JwtObject)Value).TryGetValue(key, out var property))
                {
                    return property;
                }

                return default;
            }
        }

        internal bool ContainsKey(string key)
        {
            if (Type == JwtTokenType.Object)
            {
                return ((JwtObject)Value).ContainsKey(key);
            }

            return false;
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    ((JwtObject)Value).WriteTo(ref writer, Utf8Name.Span);
                    break;
                case JwtTokenType.Array:
                    ((JwtArray)Value).WriteTo(ref writer, Utf8Name.Span);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumber(Utf8Name.Span, (long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumber(Utf8Name.Span, (double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteString(Utf8Name.Span, (string)Value, false);
                    break;
                case JwtTokenType.Utf8String:
                    writer.WriteString(Utf8Name.Span, (byte[])Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBoolean(Utf8Name.Span, (bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNull(Utf8Name.Span);
                    break;
                default:
                    Errors.ThrowNotSupportedJsonType(Type);
                    break;
            }
        }

        private string DebuggerDisplay()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                writer.WriteStartObject();
                WriteTo(ref writer);
                writer.WriteEndObject();
                writer.Flush();

                var input = bufferWriter.WrittenSpan;
                return Encoding.UTF8.GetString(input.ToArray());
            }
        }
    }
}