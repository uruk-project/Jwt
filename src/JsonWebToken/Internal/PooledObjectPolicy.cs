namespace JsonWebToken
{
    public abstract class PooledObjectPolicy<T>
    {
        public abstract T Create();
    }
}
