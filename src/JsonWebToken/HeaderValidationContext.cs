﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    public class CriticalHeaderValidationContext
    {
        public CriticalHeaderValidationContext(JwtHeader header)
        {
            Header = header;
        }

        public JwtHeader Header { get; }
    }
}