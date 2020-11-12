// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken
{
    /// <summary>Defines an JWT with a <typeparamref name="TPayload"/> payload.</summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor where TPayload : class
    {
        /// <summary>Gets or sets the payload.</summary>
        public abstract TPayload? Payload { get; set; }

        private string DebuggerDisplay()
        {
            return ToString();
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            return Header.ToString() + Environment.NewLine + "." + Environment.NewLine + Payload?.ToString();
        }
    }
}
