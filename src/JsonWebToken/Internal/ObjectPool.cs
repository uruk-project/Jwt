// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;

namespace JsonWebToken.Internal
{
    // based on https://github.com/aspnet/Common/tree/master/src/Microsoft.Extensions.ObjectPool
    /// <summary>
    /// Represent a poolable <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class ObjectPool<T> : IDisposable
        where T : class, IDisposable
    {
        private readonly ObjectWrapper[] _items;
        private readonly PooledObjectFactory<T> _policy;
        private T _firstItem;

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
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));

            // -1 due to _firstItem
            _items = new ObjectWrapper[maximumRetained - 1];
        }

        /// <summary>
        /// Gets a <typeparamref name="T"/> from the pool.
        /// </summary>
        /// <returns></returns>
        public T Get()
        {
            var item = _firstItem;

            if (item == null || Interlocked.CompareExchange(ref _firstItem, null, item) != item)
            {
                item = GetViaScan();
            }

            return item;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private T GetViaScan()
        {
            var items = _items;

            for (var i = 0; i < items.Length; i++)
            {
                var item = items[i].Element;

                if (item != null && Interlocked.CompareExchange(ref items[i].Element, null, item) == item)
                {
                    return item;
                }
            }

            return _policy.Create();
        }

        /// <summary>
        /// Returns a <typeparamref name="T"/> to the pool.
        /// </summary>
        /// <param name="pooledObject"></param>
        public void Return(T pooledObject)
        {
            if (_firstItem != null || Interlocked.CompareExchange(ref _firstItem, pooledObject, null) != null)
            {
                ReturnViaScan(pooledObject);
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

        /// <summary>
        /// Dispose the managed resources.
        /// </summary>
        public void Dispose()
        {
            var items = _items;

            for (var i = 0; i < items.Length; i++)
            {
                items[i].Element?.Dispose();
            }
        }

        // PERF: the struct wrapper avoids array-covariance-checks from the runtime when assigning to elements of the array.
        [DebuggerDisplay("{Element}")]
        private struct ObjectWrapper
        {
            public T Element;
        }
    }
}
