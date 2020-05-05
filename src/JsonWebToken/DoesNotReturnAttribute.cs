// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461 || NET47 || NETCOREAPP2_1
namespace System.Diagnostics.CodeAnalysis
{
    /// <summary>Applied to a method that will never return under any circumstance.</summary>
    [AttributeUsage(AttributeTargets.Method, Inherited = false)]
    public sealed class DoesNotReturnAttribute : Attribute
    {
    }
}
#endif