// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JWT member.
    /// </summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public readonly struct JwtMember
    {
        /// <summary>
        /// Gets the <see cref="JsonValueKind"/> of the <see cref="JwtMember"/>.
        /// </summary>
        public readonly JsonValueKind Type;

        /// <summary>
        /// Gets the value of the <see cref="JwtMember"/>.
        /// </summary>
        public readonly object? Value;

        /// <summary>
        /// Gets the value of the <see cref="JwtMember"/>.
        /// </summary>
        public readonly string Name;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, object[] value)
        {
            Type = JsonValueKind.Array;
            Value = value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, string?[] value)
        {
            Type = JsonValueKind.Array;
            Value = value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
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

            Type = JsonValueKind.Object;
            Value = value;
            Name = name;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, string value)
        {
            if (value == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JsonValueKind.String;
            Value = value;
            Name = memberName;
        }

        ///// <summary>
        ///// Initializes a new instance of the <see cref="JwtMember"/> class.
        ///// </summary>
        ///// <param name="memberName"></param>
        ///// <param name="value"></param>
        //public JwtMember(string memberName, byte[] value)
        //{
        //    if (value == null)
        //    {
        //        ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
        //    }

        //    Type = JsonValueKind.String;
        //    Value = value;
        //    Name = memberName;
        //}

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, long value)
        {
            Type = JsonValueKind.Number;
            Value = value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, int value)
        {
            Type = JsonValueKind.Number;
            Value = (long)value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, short value)
        {
            Type = JsonValueKind.Number;
            Value = (long)value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, double value)
        {
            Type = JsonValueKind.Number;
            Value = value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, float value)
        {
            Type = JsonValueKind.Number;
            Value = (double)value;
            Name = memberName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtMember"/> class.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="value"></param>
        public JwtMember(string memberName, bool value)
        {
            Type = value ? JsonValueKind.True : JsonValueKind.False;
            Value = value;
            Name = memberName;
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JsonValueKind.String:
                    writer.WriteString(Name, (string)Value!);
                    break;
                case JsonValueKind.Number:
                    if (Value is long)
                    {
                        writer.WriteNumber(Name, (long)Value!);
                    }
                    else
                    {
                        writer.WriteNumber(Name, (double)Value!);
                    }
                    break;
                case JsonValueKind.Object:
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
                case JsonValueKind.Array:
                    writer.WritePropertyName(Name);
                    JsonSerializer.Serialize(writer, Value);
                    break;
                case JsonValueKind.True:
                    writer.WriteBoolean(Name, true);
                    break;
                case JsonValueKind.False:
                    writer.WriteBoolean(Name, false);
                    break;
                case JsonValueKind.Null:
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
                WriteTo(writer);
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