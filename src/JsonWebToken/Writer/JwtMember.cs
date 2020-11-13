// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Represents a JWT member.</summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public readonly struct JwtMember
    {
        /// <summary>Gets the <see cref="JwtValueKind"/> of the <see cref="JwtMember"/>.</summary>
        public readonly JwtValueKind Type;

        /// <summary>Gets the value of the <see cref="JwtMember"/>.</summary>
        public readonly object? Value;

        /// <summary>Gets the value of the <see cref="JwtMember"/>.</summary>
        public readonly string Name;

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, object[] value)
        {
            Type = JwtValueKind.Array;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, string?[] value)
        {
            Type = JwtValueKind.Array;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public JwtMember(string name, object value)
        {
            if (name == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.name);
            }

            if (value == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtValueKind.Object;
            Value = value;
            Name = name;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, string value)
        {
            if (value == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtValueKind.String;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, long value)
        {
            Type = JwtValueKind.Int64;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, int value)
        {
            Type = JwtValueKind.Int32;
            Value = value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, short value)
        {
            Type = JwtValueKind.Int16;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, double value)
        {
            Type = JwtValueKind.Double;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, float value)
        {
            Type = JwtValueKind.Float;
            Value = value;
            Name = memberName;
        }

        /// <summary>Initializes a new instance of the <see cref="JwtMember"/> class.</summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, bool value)
        {
            Type = value ? JwtValueKind.True : JwtValueKind.False;
            Value = value;
            Name = memberName;
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtValueKind.String:
                    writer.WriteString(Name, (string)Value!);
                    break;
                case JwtValueKind.Int16:
                    writer.WriteNumber(Name, (short)Value!);
                    break;
                case JwtValueKind.Int32:
                    writer.WriteNumber(Name, (int)Value!);
                    break;
                case JwtValueKind.Int64:
                    writer.WriteNumber(Name, (long)Value!);
                    break;
                case JwtValueKind.Float:
                    writer.WriteNumber(Name, (float)Value!);
                    break;
                case JwtValueKind.Double:
                    writer.WriteNumber(Name, (double)Value!);
                    break;
                case JwtValueKind.Object:
                    if (Value is IJwtSerializable serializable)
                    {
                        writer.WritePropertyName(Name);
                        serializable.WriteTo(writer);
                    }
                    else
                    {
                        writer.WritePropertyName(Name);
                        JsonSerializer.Serialize(writer, Value, Constants.DefaultSerializerOptions);
                    }
                    break;
                case JwtValueKind.Array:
                    writer.WritePropertyName(Name);
                    JsonSerializer.Serialize(writer, Value);
                    break;
                case JwtValueKind.True:
                    writer.WriteBoolean(Name, true);
                    break;
                case JwtValueKind.False:
                    writer.WriteBoolean(Name, false);
                    break;
                case JwtValueKind.Null:
                    writer.WriteNull(Name);
                    break;
                default:
                    ThrowHelper.ThrowInvalidOperationException_NotSupportedJsonType(Type);
                    break;
            }
        }
         
        private string DebuggerDisplay()
        {
            return ToString();
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                WriteTo(writer);
                writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        private string GetDebuggerDisplay()
        {
            return ToString();
        }
    }
}