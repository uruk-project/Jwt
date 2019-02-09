// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    ///// <summary>
    ///// Represents a JWT header or payload used as descriptor.
    ///// </summary>
    //public class DescriptorDictionary
    //{
    //    private readonly List<JwtProperty> _inner = new List<JwtProperty>();

    //    /// <summary>
    //    /// Initializes a new instance of the <see cref="DescriptorDictionary"/> class.
    //    /// </summary>
    //    public DescriptorDictionary()
    //    {
    //    }

    //    // TODO : remove to tests
    //public DescriptorDictionary(JObject json)
    //{
    //    if (json == null)
    //    {
    //        throw new ArgumentNullException(nameof(json));
    //    }

    //    foreach (var property in json.Properties())
    //    {
    //        JwtProperty jwtProperty;
    //        switch (property.Value.Type)
    //        {
    //            case JTokenType.Object:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), ToJwtObject(property.Value.Value<JObject>()));
    //                break;
    //            case JTokenType.Array:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), ToJwtArray(property.Value.Value<JArray>()));
    //                break;
    //            case JTokenType.Integer:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<long>());
    //                break;
    //            case JTokenType.Float:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<double>());
    //                break;
    //            case JTokenType.String:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<string>());
    //                break;
    //            case JTokenType.Boolean:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<bool>());
    //                break;
    //            case JTokenType.Null:
    //                jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name));
    //                break;
    //            default:
    //                throw new NotSupportedException();
    //        }

    //        Add(jwtProperty);
    //    }
    //}

    //    private JwtArray ToJwtArray(JArray array)
    //    {
    //        var list = new List<JwtValue>(array.Count);
    //        for (int i = 0; i < array.Count; i++)
    //        {
    //            var value = array[i];
    //            switch (value.Type)
    //            {
    //                case JTokenType.Object:
    //                    list.Add(new JwtValue(ToJwtObject((JObject)value)));
    //                    break;
    //                case JTokenType.Array:
    //                    list.Add(new JwtValue(ToJwtArray((JArray)value)));
    //                    break;
    //                case JTokenType.Integer:
    //                    list.Add(new JwtValue((long)value));
    //                    break;
    //                case JTokenType.Float:
    //                    list.Add(new JwtValue((double)value));
    //                    break;
    //                case JTokenType.String:
    //                    list.Add(new JwtValue((string)value));
    //                    break;
    //                case JTokenType.Boolean:
    //                    list.Add(new JwtValue((bool)value));
    //                    break;
    //                case JTokenType.Null:
    //                    list.Add(new JwtValue());
    //                    break;
    //                default:
    //                    throw new NotSupportedException();
    //            }
    //        }

    //        return new JwtArray(list);
    //    }
    //    private JwtObject ToJwtObject(JObject @object)
    //    {
    //        var jwtObject = new JwtObject();
    //        foreach (var kvp in @object)
    //        {
    //            var value = kvp.Value;
    //            switch (value.Type)
    //            {
    //                case JTokenType.Object:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), ToJwtObject((JObject)value)));
    //                    break;
    //                case JTokenType.Array:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), ToJwtArray((JArray)value)));
    //                    break;
    //                case JTokenType.Integer:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), (long)value));
    //                    break;
    //                case JTokenType.Float:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), (double)value));
    //                    break;
    //                case JTokenType.String:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), (string)value));
    //                    break;
    //                case JTokenType.Boolean:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key), (bool)value));
    //                    break;
    //                case JTokenType.Null:
    //                    jwtObject.Add(new JwtProperty(Encoding.UTF8.GetBytes(kvp.Key)));
    //                    break;
    //                default:
    //                    throw new NotSupportedException();
    //            }
    //        }

    //        return jwtObject;
    //    }

    //    public JwtProperty this[int index] => _inner[index];

    //    public JwtProperty this[string key] => this[Encoding.UTF8.GetBytes(key)];

    //    public JwtProperty this[ReadOnlySpan<byte> key]
    //    {
    //        get
    //        {
    //            for (int i = 0; i < _inner.Count; i++)
    //            {
    //                if (_inner[i].Utf8Name.Span.SequenceEqual(key))
    //                {
    //                    return _inner[i];
    //                }
    //            }

    //            throw new KeyNotFoundException();
    //        }
    //    }

    //    public int Count => _inner.Count;

    //    public void Add(JwtProperty property)
    //    {
    //        // TODO : Duplicates ?
    //        _inner.Add(property);
    //    }

    //    public void Add(byte[] utf8Name, string value)
    //    {
    //        _inner.Add(new JwtProperty(utf8Name, value));
    //    }

    //    public void Replace(JwtProperty property)
    //    {
    //        for (int i = 0; i < _inner.Count; i++)
    //        {
    //            if (_inner[i].Utf8Name.Span.SequenceEqual(property.Utf8Name.Span))
    //            {
    //                _inner.RemoveAt(i);
    //                break;
    //            }
    //        }

    //        _inner.Add(property);
    //    }

    //    public bool TryGetValue(string key, out JwtProperty value)
    //    {
    //        return TryGetValue(Encoding.UTF8.GetBytes(key), out value);
    //    }

    //    public bool TryGetValue(ReadOnlySpan<byte> key, out JwtProperty value)
    //    {
    //        for (int i = 0; i < _inner.Count; i++)
    //        {
    //            var property = _inner[i];
    //            if (property.Utf8Name.Span.SequenceEqual(key))
    //            {
    //                value = property;
    //                return true;
    //            }
    //        }

    //        value = default;
    //        return false;
    //    }

    //    public bool ContainsKey(ReadOnlySpan<byte> key)
    //    {
    //        for (int i = 0; i < _inner.Count; i++)
    //        {
    //            var property = _inner[i];
    //            if (property.Utf8Name.Span.SequenceEqual(key))
    //            {
    //                return true;
    //            }
    //        }

    //        return false;
    //    }
    //}
}
