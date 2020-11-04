// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public interface IJwtSerializable
    {
        void WriteTo(Utf8JsonWriter writer);
    }
}