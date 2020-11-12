// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections;
using System.Text.Json.Serialization;

namespace JsonWebToken
{
    public abstract class SecEvent : JsonObject
    {
        [JsonIgnore]
        public abstract string Name { get; }
    }
}
