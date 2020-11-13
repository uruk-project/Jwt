// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json.Serialization;

namespace JsonWebToken
{
    /// <summary>Represents an event within a Security Event Token (SECEVENT).</summary>
    public abstract class SecEvent : JsonObject
    {
        [JsonIgnore]
        public abstract string Name { get; }

        /// <summary>Validates the current SECEVENT by checing the required members.</summary>
        public virtual void Validate() { }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void RequireAttribute(string utf8Name, JwtValueKind type)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (claim.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        /// <param name="type1"></param>
        /// <param name="type2"></param>
        protected void RequireAttribute(string utf8Name, JwtValueKind type1, JwtValueKind type2)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (claim.Type != type1 && claim.Type != type2)
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, new[] { type1, type2 });
            }
        }
    }
}
