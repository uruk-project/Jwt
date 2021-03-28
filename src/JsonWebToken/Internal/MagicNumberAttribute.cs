// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    [AttributeUsage(AttributeTargets.Field, Inherited = false, AllowMultiple = true)]
    internal sealed class MagicNumberAttribute : Attribute
    {
        readonly string _value;

        public MagicNumberAttribute(string value)
        {
            _value = value;
        }

        public string Value => _value;
    }
}
