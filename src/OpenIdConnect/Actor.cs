// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class Actor : Dictionary<string, object>
    {
        public static Actor FromJson(string json)
        {
            return (Actor)JsonConvert.DeserializeObject(json, typeof(Actor));
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.None);
        }
    }
}
