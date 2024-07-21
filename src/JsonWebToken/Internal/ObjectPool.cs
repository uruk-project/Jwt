// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;

namespace JsonWebToken
{
    // based on https://github.com/aspnet/Common/tree/master/src/Microsoft.Extensions.ObjectPool
    /// <summary>
    /// Represent a poolable <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal sealed class ObjectPool<T> : IDisposable
        where T : class, IDisposable
    {
        private volatile bool _isDisposed;

        private readonly ObjectWrapper[] _items;
        private readonly PooledObjectFactory<T> _policy;
        private T? _firstItem;

        /// <summary>
        /// Initializes a new instance of <see cref="ObjectPool{T}"/>.
        /// </summary>
        /// <param name="policy"></param>
        public ObjectPool(PooledObjectFactory<T> policy)
            : this(policy, Environment.ProcessorCount * 2)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ObjectPool{T}"/>.
        /// </summary>
        /// <param name="policy"></param>
        /// <param name="maximumRetained"></param>
        public ObjectPool(PooledObjectFactory<T> policy, int maximumRetained)
        {
            if (policy is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.policy);
            }

            _policy = policy;

            // -1 due to _firstItem
            _items = new ObjectWrapper[maximumRetained - 1];
        }

        /// <summary>
        /// Gets a <typeparamref name="T"/> from the pool.
        /// </summary>
        /// <returns></returns>
        public T Get()
        {
            if (_isDisposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var item = _firstItem;
            if (item is null || Interlocked.CompareExchange(ref _firstItem, null, item) != item)
            {
                var items = _items;
                for (var i = 0; i < items.Length; i++)
                {
                    item = items[i].Element;
                    if (item is not null && Interlocked.CompareExchange(ref items[i].Element, null, item) == item)
                    {
                        return item;
                    }
                }

                item = _policy.Create();
            }

            return item;
        }

        /// <summary>
        /// Returns a <typeparamref name="T"/> to the pool.
        /// </summary>
        /// <param name="pooledObject"></param>
        public void Return(T pooledObject)
        {
            // When the pool is disposed or the obj is not returned to the pool, dispose it
            if (_isDisposed || !ReturnCore(pooledObject))
            {
                DisposeItem(pooledObject);
            }
        }

        private bool ReturnCore(T obj)
        {
            bool returnedTooPool = false;

            if (_firstItem is null && Interlocked.CompareExchange(ref _firstItem, obj, null) is null)
            {
                returnedTooPool = true;
            }
            else
            {
                var items = _items;
                for (var i = 0; i < items.Length && !(returnedTooPool = Interlocked.CompareExchange(ref items[i].Element, obj, null!) is null); i++)
                {
                }
            }

            return returnedTooPool;
        }

        /// <summary>
        /// Dispose the managed resources.
        /// </summary>
        public void Dispose()
        {
            _isDisposed = true;

            DisposeItem(_firstItem);
            _firstItem = null;

            ObjectWrapper[] items = _items;
            for (var i = 0; i < items.Length; i++)
            {
                DisposeItem(items[i].Element);
                items[i].Element = null;
            }
        }

        private static void DisposeItem(T? item)
        {
            if (item is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        // PERF: the struct wrapper avoids array-covariance-checks from the runtime when assigning to elements of the array.
        [DebuggerDisplay("{Element}")]
        private struct ObjectWrapper
        {
            public T? Element;
        }
    }
}
