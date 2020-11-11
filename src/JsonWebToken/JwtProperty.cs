//// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
//// Licensed under the MIT license. See LICENSE in the project root for license information.

//using System;
//using System.Diagnostics;
//using System.Text.Json;
//using JsonWebToken.Internal;

//namespace JsonWebToken
//{
//    /// <summary>
//    /// Represents a JSON property.
//    /// </summary>
//    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
//    public readonly struct JwtProperty
//    {
//        internal static ReadOnlySpan<byte> GetWellKnowName(WellKnownProperty wellKnownName)
//        {
//            return wellKnownName switch
//            {
//                WellKnownProperty.Exp => Claims.ExpUtf8,
//                WellKnownProperty.Aud => Claims.AudUtf8,
//                WellKnownProperty.Iat => Claims.IatUtf8,
//                WellKnownProperty.Iss => Claims.IssUtf8,
//                WellKnownProperty.Jti => Claims.JtiUtf8,
//                WellKnownProperty.Nbf => Claims.NbfUtf8,
//                WellKnownProperty.Sub => Claims.SubUtf8,
//                WellKnownProperty.Typ => HeaderParameters.TypUtf8,
//                WellKnownProperty.Zip => HeaderParameters.ZipUtf8,
//                WellKnownProperty.Kid => HeaderParameters.KidUtf8,
//                WellKnownProperty.Alg => HeaderParameters.AlgUtf8,
//                WellKnownProperty.Enc => HeaderParameters.EncUtf8,
//                WellKnownProperty.Cty => HeaderParameters.CtyUtf8,
//                _ => ThrowHelper.ThrowArgumentOutOfRangeException_WellKnowProperty(wellKnownName)
//            };
//        }

//        /// <summary>
//        /// Gets whether the <see cref="JwtProperty"/> is empty.
//        /// </summary>
//        public bool IsEmpty => WellKnownName == 0 && _utf8Name.IsEmpty;

//        /// <summary>
//        /// Gets the name of the <see cref="JwtProperty"/> in its UTF-8 representation.
//        /// </summary>
//        public ReadOnlySpan<byte> Utf8Name => WellKnownName == 0 ? _utf8Name.Span : GetWellKnowName(WellKnownName);

//        /// <summary>
//        /// Gets the <see cref="JwtTokenType"/> of the <see cref="JwtProperty"/>.
//        /// </summary>
//        public readonly JwtTokenType Type;

//        private readonly ReadOnlyMemory<byte> _utf8Name;

//        /// <summary>
//        /// Gets the <see cref="WellKnownProperty"/> value representing a well known property name.
//        /// </summary>
//        public readonly WellKnownProperty WellKnownName;

//        /// <summary>
//        /// Gets the value of the <see cref="JwtProperty"/>.
//        /// </summary>
//        public readonly object? Value;

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, JwtArray value)
//        {
//            Type = JwtTokenType.Array;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="wellKnown"></param>
//        /// <param name="value"></param>
//        public JwtProperty(WellKnownProperty wellKnown, JwtArray value)
//        {
//            Type = JwtTokenType.Array;
//            WellKnownName = wellKnown;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, JwtObject value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.Object;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, string? value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.String;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, byte[] value)
//        {
//            Type = JwtTokenType.Utf8String;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, long value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, int value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, double value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, float value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name, bool value)
//        {
//            Type = JwtTokenType.Boolean;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        public JwtProperty(ReadOnlySpan<byte> utf8Name)
//        {
//            Type = JwtTokenType.Null;
//            WellKnownName = 0;
//            _utf8Name = utf8Name.ToArray();
//            Value = null;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JwtArray value)
//        {
//            Type = JwtTokenType.Array;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JwtObject value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.Object;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, string value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.String;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, byte[] value)
//        {
//            Type = JwtTokenType.Utf8String;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, long value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, int value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, double value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, float value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name, bool value)
//        {
//            Type = JwtTokenType.Boolean;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
//        /// </summary>
//        /// <param name="utf8Name"></param>
//        public JwtProperty(ReadOnlyMemory<byte> utf8Name)
//        {
//            Type = JwtTokenType.Null;
//            WellKnownName = 0;
//            _utf8Name = utf8Name;
//            Value = null;
//        }


//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, JwtArray value)
//        {
//            Type = JwtTokenType.Array;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, JwtObject value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.Object;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, string value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.String;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, byte[] value)
//        {
//            Type = JwtTokenType.Utf8String;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, long value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, int value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = (long)value; // cast to long required due to boxing
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, double value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, float value)
//        {
//            Type = JwtTokenType.Float;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="name"></param>
//        /// <param name="value"></param>
//        public JwtProperty(string name, bool value)
//        {
//            Type = JwtTokenType.Boolean;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
//        /// </summary>
//        /// <param name="name"></param>
//        public JwtProperty(string name)
//        {
//            Type = JwtTokenType.Null;
//            WellKnownName = 0;
//            _utf8Name = Utf8.GetBytes(name);
//            Value = null;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="wellKnown"></param>
//        /// <param name="value"></param>
//        public JwtProperty(WellKnownProperty wellKnown, string value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.String;
//            WellKnownName = wellKnown;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="wellKnown"></param>
//        /// <param name="value"></param>
//        public JwtProperty(WellKnownProperty wellKnown, byte[] value)
//        {
//            if (value == null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.Utf8String;
//            WellKnownName = wellKnown;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="wellKnown"></param>
//        /// <param name="value"></param>
//        public JwtProperty(WellKnownProperty wellKnown, long value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = wellKnown;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="wellKnown"></param>
//        /// <param name="value"></param>
//        public JwtProperty(WellKnownProperty wellKnown, double value)
//        {
//            Type = JwtTokenType.Integer;
//            WellKnownName = wellKnown;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="value"></param>
//        public JwtProperty(EncryptionAlgorithm value)
//        {
//            if (value is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.EncryptionAlgorithm;
//            WellKnownName = WellKnownProperty.Enc;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="value"></param>
//        public JwtProperty(SignatureAlgorithm value)
//        {
//            if (value is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.SignatureAlgorithm;
//            WellKnownName = WellKnownProperty.Alg;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="value"></param>
//        public JwtProperty(KeyManagementAlgorithm value)
//        {
//            if (value is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.KeyManagementAlgorithm;
//            WellKnownName = WellKnownProperty.Alg;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
//        /// </summary>
//        /// <param name="value"></param>
//        public JwtProperty(CompressionAlgorithm value)
//        {
//            if (value is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
//            }

//            Type = JwtTokenType.CompressionAlgorithm;
//            WellKnownName = WellKnownProperty.Alg;
//            _utf8Name = default;
//            Value = value;
//        }

//        /// <summary>
//        /// Gets or sets the <see cref="JwtProperty"/> at the specified key;
//        /// </summary>
//        /// <param name="key"></param>
//        /// <returns></returns>
//        public JwtProperty this[string key]
//        {
//            get
//            {
//                if (Type == JwtTokenType.Object && ((JwtObject)Value!).TryGetValue(key, out var property))
//                {
//                    return property;
//                }

//                return default;
//            }
//        }

//        /// <summary>
//        /// Gets whether the <paramref name="key"/> is present in the current <see cref="JwtProperty"/> at the specified key. 
//        /// Return always <c>false</c> if the <see cref="JwtProperty"/> is not a JSON object.
//        /// </summary>
//        /// <param name="key"></param>
//        /// <returns></returns>
//        public bool ContainsKey(string key)
//        {
//            if (Type == JwtTokenType.Object)
//            {
//                return ((JwtObject)Value!).ContainsKey(key);
//            }

//            return false;
//        }

//        internal void WriteTo(Utf8JsonWriter writer)
//        {
//            switch (Type)
//            {
//                case JwtTokenType.Object:
//                    ((JwtObject)Value!).WriteTo(writer, Utf8Name);
//                    break;
//                case JwtTokenType.Array:
//                    ((JwtArray)Value!).WriteTo(writer, Utf8Name);
//                    break;
//                case JwtTokenType.Integer:
//                    writer.WriteNumber(Utf8Name, (long)Value!);
//                    break;
//                case JwtTokenType.Float:
//                    if (Value is double)
//                    {
//                        writer.WriteNumber(Utf8Name, (double)Value!);
//                    }
//                    else
//                    {
//                        writer.WriteNumber(Utf8Name, (float)Value!);
//                    }
//                    break;
//                case JwtTokenType.String:
//                    writer.WriteString(Utf8Name, (string)Value!);
//                    break;
//                case JwtTokenType.Utf8String:
//                    writer.WriteString(Utf8Name, (byte[])Value!);
//                    break;
//                case JwtTokenType.Boolean:
//                    writer.WriteBoolean(Utf8Name, (bool)Value!);
//                    break;
//                case JwtTokenType.Null:
//                    writer.WriteNull(Utf8Name);
//                    break;
//                default:
//                    ThrowHelper.ThrowInvalidOperationException_NotSupportedJsonType(Type);
//                    break;
//            }
//        }

//        private string DebuggerDisplay()
//        {
//            using var bufferWriter = new PooledByteBufferWriter();
//            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
//            {
//                writer.WriteStartObject();
//                WriteTo(writer);
//                writer.WriteEndObject();
//            }

//            var input = bufferWriter.WrittenSpan;
//            return Utf8.GetString(input);
//        }
//    }
//}