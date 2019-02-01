// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an JWT with a <typeparamref name="TPayload"/> payload.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class JwtDescriptor<TPayload> : JwtDescriptor where TPayload : class
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public JwtDescriptor(DescriptorDictionary header, TPayload payload)
            : base(header)
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptor{TPayload}"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JwtDescriptor(TPayload payload)
            : base()
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        /// <summary>
        /// Gets or sets the payload.
        /// </summary>
        public TPayload Payload { get; set; }

        private string DebuggerDisplay()
        {
            return Serialize(Header, Formatting.Indented) + "." + Serialize(Payload, Formatting.Indented);
        }
    }
}
