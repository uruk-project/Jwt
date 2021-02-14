// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NET47
namespace JsonWebToken
{
    internal class RuntimeInformation
    {
        internal static bool IsOSPlatform(OSPlatform os)
            => false;
    }
}
#endif