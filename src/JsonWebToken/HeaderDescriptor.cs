// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JWT header used as descriptor.
    /// </summary>
    public class HeaderDescriptor : Dictionary<string, object>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HeaderDescriptor"/> class.
        /// </summary>
        public HeaderDescriptor()
            : base(2)
        {
        }
    }
}
