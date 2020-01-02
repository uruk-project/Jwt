﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents an <see cref="Exception"/> caused by an error in the <see cref="JwtDescriptor"/>. 
    /// </summary>
    public sealed class JwtDescriptorException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JwtDescriptorException"/>.
        /// </summary>
        /// <param name="message"></param>
        public JwtDescriptorException(string message)
            : base(message)
        {
        }
    }
}