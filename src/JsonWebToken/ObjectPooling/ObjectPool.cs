using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;

namespace JsonWebToken.ObjectPooling
{
    // based on https://github.com/aspnet/Common/tree/master/src/Microsoft.Extensions.ObjectPool
    public class ObjectPool<T> : IDisposable
        where T : class, IDisposable
    {
        private readonly ObjectWrapper[] _items;
        private readonly PooledObjectPolicy<T> _policy;
        private T _firstItem;

        public ObjectPool(PooledObjectPolicy<T> policy)
            : this(policy, Environment.ProcessorCount * 2)
        {
        }

        public ObjectPool(PooledObjectPolicy<T> policy, int maximumRetained)
        {
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));

            // -1 due to _firstItem
            _items = new ObjectWrapper[maximumRetained - 1];
        }

        public T Get()
        {
            T item = _firstItem;

            if (item == null || Interlocked.CompareExchange(ref _firstItem, null, item) != item)
            {
                item = GetViaScan();
            }

            return item;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private T GetViaScan()
        {
            ObjectWrapper[] items = _items;
            T item = null;

            for (var i = 0; i < items.Length; i++)
            {
                item = items[i];

                if (item != null && Interlocked.CompareExchange(ref items[i].Element, null, item) == item)
                {
                    break;
                }
            }

            return item ?? _policy.Create();
        }

        public void Return(T pooledObject)
        {
            if (_policy.Return(pooledObject))
            {
                if (_firstItem != null || Interlocked.CompareExchange(ref _firstItem, pooledObject, null) != null)
                {
                    ReturnViaScan(pooledObject);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ReturnViaScan(T pooledObject)
        {
            ObjectWrapper[] items = _items;

            for (var i = 0; i < items.Length && Interlocked.CompareExchange(ref items[i].Element, pooledObject, null) != null; ++i)
            {
            }
        }

        public void Dispose()
        {
            ObjectWrapper[] items = _items;
            T item = null;
            for (var i = 0; i < items.Length; i++)
            {
                item = items[i];

                if (item != null)
                {
                    item.Dispose();
                }
            }
        }

        [DebuggerDisplay("{Element}")]
        private struct ObjectWrapper
        {
            public T Element;

            public ObjectWrapper(T element) => Element = element;

            public static implicit operator T(ObjectWrapper wrapper) => wrapper.Element;
        }
    }
}
