﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a <typeparamref name="TPayload"/> payload.</summary>
    [Obsolete("This class is obsolete. use the class JweDescriptorBase<TPayload> instead.", true)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class EncryptedJwtDescriptor<TPayload>
    {
    }
}