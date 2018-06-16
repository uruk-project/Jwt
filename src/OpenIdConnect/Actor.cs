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
