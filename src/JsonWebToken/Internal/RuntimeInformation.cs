// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NET47 || NET461
namespace JsonWebToken
{
    internal class RuntimeInformation
    {
        // NET47 is only available on Windows
        internal static bool IsOSPlatform(OSPlatform os)
            => os == OSPlatform.Windows;
    }
}
#endif