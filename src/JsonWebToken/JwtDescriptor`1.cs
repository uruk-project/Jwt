﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an JWT with a <typeparamref name="TPayload"/> payload.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        protected JwtDescriptor(JwtObject header, TPayload payload)
            : base(header)
        {
            if (payload is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
            }

            Payload = payload;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="payload"></param>
        protected JwtDescriptor(TPayload payload)
            : base()
        {
            if (payload is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
            }

            Payload = payload;
        }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        public TPayload Payload { get; set; }

        private string DebuggerDisplay()
        {
            return ToString();
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            return Header?.ToString() + Environment.NewLine + "." + Environment.NewLine + Payload?.ToString();
        }
    }
}
