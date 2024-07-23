using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace JsonWebToken.Tests
{
    public class AlgorithmFixture<T> : IEnumerable<object[]>
    {
        public IEnumerator<object[]> GetEnumerator()
        {
            var type = typeof(T);
            var properties = type.GetFields(BindingFlags.Public | BindingFlags.Static).Where(p => typeof(T).IsAssignableFrom(p.FieldType));
            foreach (var item in properties)
            {
                var obsolete = item.GetCustomAttribute<ObsoleteAttribute>();
                if (obsolete is null)
                {
                    yield return new object[] { item.GetValue(null) };
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }
    }
}