﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines an abstract class for representing a JWT.</summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public abstract partial class JwtDescriptor
    {
        private JwtHeader _header;
        private bool _headerInitialized;

        /// <summary>Initializes a new instance of <see cref="JwtDescriptor"/>.</summary>
        protected JwtDescriptor()
        {
            _header = new JwtHeader();
        }

        /// <summary>Gets the parameters header.</summary>
        public JwtHeader Header
        {
            get => _header;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                if (_headerInitialized)
                {
                    ThrowHelper.ThrowInvalidOperationException_AlreadyInitialized(ExceptionArgument.header);
                }

                _headerInitialized = true;
                _header.CopyTo(value);
                _header = value;
            }
        }

        /// <summary>Encodes the current <see cref="JwtDescriptor"/> into it compact representation.</summary>
        public abstract void Encode(EncodingContext context);

        /// <summary>Validates the current <see cref="JwtDescriptor"/>.</summary>
        public abstract void Validate();

        /// <summary>Validates the presence and the type of a required claim.</summary>
        protected void CheckRequiredHeaderParameterAsString(JsonEncodedText utf8Name)
        {
            if (!_header.TryGetValue(utf8Name, out var parameter))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (!parameter.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, new[] {
                    JwtValueKind.String,
                    JwtValueKind.JsonEncodedString });
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        protected void CheckRequiredHeaderParameterAsNumber(JsonEncodedText utf8Name)
        {
            if (!_header.TryGetValue(utf8Name, out var parameter))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (!parameter.Type.IsNumber())
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt32,
                    JwtValueKind.UInt64,
                    JwtValueKind.Float,
                    JwtValueKind.Double});
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        protected void CheckRequiredHeaderParameterAsInteger(JsonEncodedText utf8Name)
        {
            if (!_header.TryGetValue(utf8Name, out var parameter))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (!parameter.Type.IsInteger())
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt32,
                    JwtValueKind.UInt64});
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        protected void CheckRequiredHeaderParameterAsStringOrArray(JsonEncodedText utf8Name)
        {
            if (!_header.TryGetValue(utf8Name, out var parameter))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (!parameter.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, new[] {
                    JwtValueKind.String,
                    JwtValueKind.JsonEncodedString,
                    JwtValueKind.Array });
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        protected void CheckRequiredHeaderParameterAsObject(JsonEncodedText utf8Name)
        {
            if (!_header.TryGetValue(utf8Name, out var parameter))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (parameter.Type != JwtValueKind.Object)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, JwtValueKind.Object);
            }
        }

        private string GetDebuggerDisplay()
            => _header.ToString();
    }
}