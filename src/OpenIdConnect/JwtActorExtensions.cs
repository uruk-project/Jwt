using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public static class JwtActorExtensions
    {
        public static Actor GetActor(this JsonWebToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var json = token.Payload[Claims.Act]?.Value<string>();
            return json == null ? null : Actor.FromJson(json);
        }
    }
}
