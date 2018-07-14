namespace JsonWebToken.ObjectPooling
{
    public abstract class PooledObjectPolicy<T>
    {
        public abstract T Create();

        public abstract bool Return(T obj);
    }
}
