// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Provides a way to write a to a <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public interface IJwtSerializable
    {
        /// <summary>
        /// Writes the current object to a <see cref="Utf8JsonWriter"/>.
        /// </summary>
        /// <param name="writer"></param>
        void WriteTo(Utf8JsonWriter writer);
    }

    /// <summary>
    /// Provides a way to write a to a <see cref="Utf8JsonWriter"/>.
    /// </summary>
    public interface IJwtNamedSerializable
    {
        /// <summary>
        /// Writes the current object to a <see cref="Utf8JsonWriter"/>.
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="name"></param>
        void WriteTo(Utf8JsonWriter writer, string name);
    }
}