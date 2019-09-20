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
        /// <summary>
        /// A <see cref="JwtValue"/> with <c>null</c> value.
        /// </summary>
        public static readonly JwtValue Null = default;

        /// <summary>
        /// A <see cref="JwtValue"/> with <c>true</c> value.
        /// </summary>
        public static readonly JwtValue True = new JwtValue(true);

        /// <summary>
        /// A <see cref="JwtValue"/> with <c>false</c> value.
        /// </summary>
        public static readonly JwtValue False = new JwtValue(false);

        /// <summary>
        /// Gets the <see cref="JwtTokenType"/> of the <see cref="JwtValue"/>.
        /// </summary>
        public readonly JwtTokenType Type;

        /// <summary>
        /// Gets the value of the <see cref="JwtValue"/>.
        /// </summary>
        public readonly object? Value;

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
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
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
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
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
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
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
            Value = (double)value;
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

        internal void WriteTo(Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    ((JwtObject)Value!).WriteTo(writer);
                    break;
                case JwtTokenType.Array:
                    ((JwtArray)Value!).WriteTo(writer);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumberValue((long)Value!);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumberValue((double)Value!);
                    break;
                case JwtTokenType.String:
                    writer.WriteStringValue((string)Value!);
                    break;
                case JwtTokenType.Utf8String:
                    writer.WriteStringValue((byte[])Value!);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBooleanValue((bool)Value!);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNullValue();
                    break;
                default:
                    ThrowHelper.ThrowInvalidOperationException_NotSupportedJsonType(Type);
                    break;
            }
        }

        private string DebuggerDisplay()
        {
            using (var bufferWriter = new ArrayBufferWriter())
            {
                using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
                {
                    WriteTo(writer);
                }

                var input = bufferWriter.WrittenSpan;
#if NETSTANDARD2_0 || NET461
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }
    }
}