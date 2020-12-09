// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Method | AttributeTargets.Constructor, Inherited = false)]
    internal sealed class StackTraceHiddenAttribute : Attribute
    {
        public StackTraceHiddenAttribute()
        {
        }
    }
}
