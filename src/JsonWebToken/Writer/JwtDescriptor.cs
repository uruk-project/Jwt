// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines an abstract class for representing a JWT.</summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor
    {
        private JwtHeader _header;

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

                _header.CopyTo(value);
                _header = value;
            }
        }

        /// <summary>Encodes the current <see cref="JwtDescriptor"/> into it compact representation.</summary>
        /// <param name="context"></param>
        public abstract void Encode(EncodingContext context);

        /// <summary>Validates the current <see cref="JwtDescriptor"/>.</summary>
        public virtual void Validate()
        {
        }

        /// <summary>Validates the presence and the type of a required header.</summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind type)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            if (tokenType.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>Validates the presence and the type of a required header.</summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void CheckRequiredHeader(string utf8Name, JsonValueKind[] types)
        {
            if (!Header.TryGetValue(utf8Name, out var tokenType))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (tokenType.Type == types[i])
                {
                    return;
                }
            }

            ThrowHelper.ThrowJwtDescriptorException_HeaderMustBeOfType(utf8Name, types);
        }
    }
}