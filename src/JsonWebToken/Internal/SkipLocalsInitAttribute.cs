// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !SUPPORT_SKIPLOCALINIT
using System;

namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Indicates to the compiler that the .locals init flag should not be set in nested method headers when emitting to metadata.
    /// </summary>
    [AttributeUsage(AttributeTargets.Module | AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Event | AttributeTargets.Interface, Inherited = false)]
    public sealed class SkipLocalsInitAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of the System.Runtime.CompilerServices.SkipLocalsInitAttribute class.
        /// </summary>
        public SkipLocalsInitAttribute() { }
    }
}
#endif
