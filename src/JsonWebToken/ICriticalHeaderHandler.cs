// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    public interface ICriticalHeaderHandler
    {
        bool TryHandle(CriticalHeaderValidationContext context, string headerName);
    }
}
