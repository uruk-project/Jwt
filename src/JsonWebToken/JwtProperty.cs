// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines the well known JWT properties.
    /// </summary>
    public enum WellKnownProperty
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,

        /// <summary>
        /// exp
        /// </summary>
        Exp,

        /// <summary>
        /// aud
        /// </summary>
        Aud,

        /// <summary>
        /// iat
        /// </summary>
        Iat,

        /// <summary>
        /// iss
        /// </summary>
        Iss,

        /// <summary>
        /// jti
        /// </summary>
        Jti,

        /// <summary>
        /// nbf
        /// </summary>
        Nbf,

        /// <summary>
        /// kid
        /// </summary>
        Kid,

        /// <summary>
        /// alg
        /// </summary>
        Alg,

        /// <summary>
        /// enc
        /// </summary>
        Enc,

        /// <summary>
        /// cty
        /// </summary>
        Cty,

        /// <summary>
        /// typ
        /// </summary>
        Typ,

        /// <summary>
        /// zip
        /// </summary>
        Zip,

        /// <summary>
        /// sub
        /// </summary>
        Sub
    }

    /// <summary>
    /// Represents a JSON property.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public readonly struct JwtProperty
    {
        internal static ReadOnlySpan<byte> GetWellKnowName(WellKnownProperty wellKnownName)
        {
            switch (wellKnownName)
            {
                case WellKnownProperty.Exp:
                    return Claims.ExpUtf8;
                case WellKnownProperty.Aud:
                    return Claims.AudUtf8;
                case WellKnownProperty.Iat:
                    return Claims.IatUtf8;
                case WellKnownProperty.Iss:
                    return Claims.IssUtf8;
                case WellKnownProperty.Jti:
                    return Claims.JtiUtf8;
                case WellKnownProperty.Nbf:
                    return Claims.NbfUtf8;
                case WellKnownProperty.Kid:
                    return HeaderParameters.KidUtf8;
                case WellKnownProperty.Alg:
                    return HeaderParameters.AlgUtf8;
                case WellKnownProperty.Enc:
                    return HeaderParameters.EncUtf8;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets whether the <see cref="JwtProperty"/> is empty.
        /// </summary>
        public bool IsEmpty => WellKnownName == 0 && _utf8Name.IsEmpty;

        /// <summary>
        /// Gets the name of the <see cref="JwtProperty"/> in its UTF-8 representation.
        /// </summary>
        public ReadOnlySpan<byte> Utf8Name => WellKnownName == 0 ? _utf8Name.Span : GetWellKnowName();

        private ReadOnlySpan<byte> GetWellKnowName()
        {
            switch (WellKnownName)
            {
                case WellKnownProperty.None:
                    return _utf8Name.Span;
                case WellKnownProperty.Exp:
                    return Claims.ExpUtf8;
                case WellKnownProperty.Aud:
                    return Claims.AudUtf8;
                case WellKnownProperty.Iat:
                    return Claims.IatUtf8;
                case WellKnownProperty.Iss:
                    return Claims.IssUtf8;
                case WellKnownProperty.Jti:
                    return Claims.JtiUtf8;
                case WellKnownProperty.Nbf:
                    return Claims.NbfUtf8;
                case WellKnownProperty.Kid:
                    return HeaderParameters.KidUtf8;
                case WellKnownProperty.Alg:
                    return HeaderParameters.AlgUtf8;
                case WellKnownProperty.Enc:
                    return HeaderParameters.EncUtf8;
                case WellKnownProperty.Typ:
                    return HeaderParameters.TypUtf8;
                case WellKnownProperty.Zip:
                    return HeaderParameters.ZipUtf8;
                case WellKnownProperty.Cty:
                    return HeaderParameters.CtyUtf8;
                default:
                    return _utf8Name.Span;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtTokenType"/> of the <see cref="JwtProperty"/>.
        /// </summary>
        public readonly JwtTokenType Type;

        private readonly ReadOnlyMemory<byte> _utf8Name;

        /// <summary>
        /// Gets the <see cref="WellKnownProperty"/> value representing a well known property name.
        /// </summary>
        public readonly WellKnownProperty WellKnownName;

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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="utf8Name"></param>
        public JwtProperty(ReadOnlySpan<byte> utf8Name)
        {
            Type = JwtTokenType.Null;
            WellKnownName = 0;
            _utf8Name = utf8Name.ToArray();
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = utf8Name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="utf8Name"></param>
        public JwtProperty(ReadOnlyMemory<byte> utf8Name)
        {
            Type = JwtTokenType.Null;
            WellKnownName = 0;
            _utf8Name = utf8Name;
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/> with a <c>null</c> value.
        /// </summary>
        /// <param name="name"></param>
        public JwtProperty(string name)
        {
            Type = JwtTokenType.Null;
            WellKnownName = 0;
            _utf8Name = Encoding.UTF8.GetBytes(name);
            Value = null;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="wellKnown"></param>
        /// <param name="value"></param>
        public JwtProperty(WellKnownProperty wellKnown, string value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.String;
            WellKnownName = wellKnown;
            _utf8Name = default;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="wellKnown"></param>
        /// <param name="value"></param>
        public JwtProperty(WellKnownProperty wellKnown, byte[] value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.Utf8String;
            WellKnownName = wellKnown;
            _utf8Name = default;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="value"></param>
        public JwtProperty(EncryptionAlgorithm value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.EncryptionAlgorithm;
            WellKnownName = WellKnownProperty.Enc;
            _utf8Name = default;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="value"></param>
        public JwtProperty(SignatureAlgorithm value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.SignatureAlgorithm;
            WellKnownName = WellKnownProperty.Alg;
            _utf8Name = default;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="value"></param>
        public JwtProperty(KeyManagementAlgorithm value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.KeyManagementAlgorithm;
            WellKnownName = WellKnownProperty.Alg;
            _utf8Name = default;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the struct <see cref="JwtProperty"/>.
        /// </summary>
        /// <param name="value"></param>
        public JwtProperty(CompressionAlgorithm value)
        {
            if (value == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.value);
            }

            Type = JwtTokenType.CompressionAlgorithm;
            WellKnownName = WellKnownProperty.Alg;
            _utf8Name = default;
            Value = value;
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
                    ((JwtObject)Value).WriteTo(ref writer, Utf8Name);
                    break;
                case JwtTokenType.Array:
                    ((JwtArray)Value).WriteTo(ref writer, Utf8Name);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumber(Utf8Name, (long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumber(Utf8Name, (double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteString(Utf8Name, (string)Value, false);
                    break;
                case JwtTokenType.Utf8String:
                    writer.WriteString(Utf8Name, (byte[])Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBoolean(Utf8Name, (bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNull(Utf8Name);
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