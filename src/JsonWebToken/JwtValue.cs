// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON value.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtValue
    {
        public static readonly JwtValue Null = default;
        public static readonly JwtValue True = new JwtValue(true);
        public static readonly JwtValue False = new JwtValue(false);

        /// <summary>
        /// Gets the <see cref="JwtTokenType"/> of the <see cref="JwtValue"/>.
        /// </summary>
        public readonly JwtTokenType Type;

        /// <summary>
        /// Gets the value of the <see cref="JwtValue"/>.
        /// </summary>
        public readonly object Value;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(JwtArray value)
        {
            Type = JwtTokenType.Array;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(JwtObject value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(nameof(value));
            }

            Type = JwtTokenType.Object;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(string value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(nameof(value));
            }

            Type = JwtTokenType.String;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(byte[] value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(nameof(value));
            }

            Type = JwtTokenType.Utf8String;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(long value)
        {
            Type = JwtTokenType.Integer;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(int value)
        {
            Type = JwtTokenType.Integer;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(double value)
        {
            Type = JwtTokenType.Float;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(float value)
        {
            Type = JwtTokenType.Float;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtValue"/> class.
        /// </summary>
        /// <param name="value"></param>
        public JwtValue(bool value)
        {
            Type = JwtTokenType.Boolean;
            Value = value;
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    ((JwtObject)Value).WriteTo(ref writer);
                    break;
                case JwtTokenType.Array:
                    ((JwtArray)Value).WriteTo(ref writer);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumberValue((long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumberValue((double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteStringValue((string)Value, false);
                    break;
                case JwtTokenType.Utf8String:
                    writer.WriteStringValue((byte[])Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBooleanValue((bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNullValue();
                    break;
                default:
                    Errors.ThrowNotSupportedJsonType(Type);
                    break;
            }
        }

        private string DebuggerDisplay()
        {
            var bufferWriter = new ArrayBufferWriter<byte>();
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