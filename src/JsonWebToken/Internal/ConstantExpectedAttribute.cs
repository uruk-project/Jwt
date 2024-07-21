// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NET5_0 || NET6_0 || NETCOREAPP3_1
namespace System.Diagnostics.CodeAnalysis
{
    /// <summary> Indicates that the specified method parameter expects a constant.</summary>
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    public sealed class ConstantExpectedAttribute : Attribute
    {
        /// <summary>Gets or sets the maximum bound of the expected constant, inclusive.</summary>
        public object? Max { get; set; }

        /// <summary>Gets or sets the minimum bound of the expected constant, inclusive.</summary>
        public object? Min { get; set; }
    }
}
#endif