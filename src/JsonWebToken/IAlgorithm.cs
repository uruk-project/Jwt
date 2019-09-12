// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public interface IAlgorithm
    {
        public byte[] Utf8Name { get; }

        public string Name { get; }
    }
}