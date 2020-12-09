// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public static class JsonObjectExtensions
    {
        /// <summary>
        /// Adds the claim of type <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public static void Add(this JsonObject jsonObject, SecEvent secEvent)
        {
            jsonObject.Add(secEvent.Name, secEvent);
        }
    }    
}
