namespace JsonWebToken.Internal
{
    public abstract class PooledObjectPolicy<T>
    {
        public abstract T Create();
    }
}
