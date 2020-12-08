// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    /// <summary>This struct is obsolete. Represents a JSON array.</summary>
    [Obsolete("This struct is obsolete. Use C# Array instead.", true)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public readonly struct JwtArray
    {
    }
}
