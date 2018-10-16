using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a provider of <see cref="JsonWebKey"/>.
    /// </summary>
    public interface IKeyProvider
    {
        IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header);
    }
}
