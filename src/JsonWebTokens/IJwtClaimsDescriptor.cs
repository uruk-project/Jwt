using System;
using System.Collections.Generic;

namespace JsonWebTokens
{
    public interface IJwtPayloadDescriptor
    {
        string Subject { get; set; }
        IReadOnlyList<string> Audiences { get; set; }
        DateTime? ExpirationTime { get; set; }
        DateTime? IssuedAt { get; set; }
        string Issuer { get; set; }
        string JwtId { get; set; }
        DateTime? NotBefore { get; set; }
    }
}