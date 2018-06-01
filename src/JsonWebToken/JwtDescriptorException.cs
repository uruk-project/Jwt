using System;

namespace JsonWebToken
{
    public class JwtDescriptorException : Exception
    {
        public JwtDescriptorException(string message)
            : base(message)
        {
        }
    }
}