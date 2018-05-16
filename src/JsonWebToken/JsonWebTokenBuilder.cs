namespace JsonWebToken
{
    public class JsonWebTokenBuilder
    {
        private readonly JsonWebTokenDescriptor _descriptor = new JsonWebTokenDescriptor();

        public JsonWebTokenDescriptor Build()
        {
            return _descriptor;
        }
    }
}
