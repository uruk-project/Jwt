// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public sealed class JwtDescriptorException : Exception
    {
        public JwtDescriptorException(string message)
            : base(message)
        {
        }
    }
}