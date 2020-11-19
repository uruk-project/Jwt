// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace JsonWebToken
{
    /// <summary>Represents an event within a Security Event Token (SECEVENT).</summary>
    public abstract class SecEvent : JsonObject
    {
        public static readonly JsonEncodedText SubjectAttribute = JsonEncodedText.Encode("subject");

        [JsonIgnore]
        public abstract JsonEncodedText Name { get; }

        /// <summary>Validates the current SECEVENT by checking the required members.</summary>
        public virtual void Validate() { }

        /// <summary>Validates the presence and the type of a required member.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredMemberAsString(JsonEncodedText utf8Name)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (!claim.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString });
            }
        }

        /// <summary>Validates the presence and the type of a required member.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredMemberAsNumber(JsonEncodedText utf8Name)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (!claim.Type.IsNumber())
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int16,
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.Float,
                    JwtValueKind.Double});
            }
        }
        /// <summary>Validates the presence and the type of a required member.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredMemberAsInteger(JsonEncodedText utf8Name)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (!claim.Type.IsInteger())
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int16,
                    JwtValueKind.Int32,
                    JwtValueKind.Int64});
            }
        }

        /// <summary>Validates the presence and the type of a required member.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredMemberAsStringOrArray(JsonEncodedText utf8Name)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (!claim.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString, JwtValueKind.Array });
            }
        }

        /// <summary>Validates the presence and the type of a required member.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredMemberAsObject(JsonEncodedText utf8Name)
        {
            if (!TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeIsRequired(utf8Name);
            }

            if (claim.Type != JwtValueKind.Object)
            {
                ThrowHelper.ThrowJwtDescriptorException_SecEventAttributeMustBeOfType(utf8Name, JwtValueKind.Object);
            }
        }
    }
}
