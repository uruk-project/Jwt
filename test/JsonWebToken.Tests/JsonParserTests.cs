using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonParserTests
    {
        [Theory]
        //[InlineData("{}")]
        //[InlineData("{\"hello\": \"world\"}")]
        //[InlineData("{\"string\":\"string\",\"number\":5,\"decimal\":3516512.13512,\"long\":9.22337203685478E+18,\"notLong\":922854776000.12,\"boolean\":false,\"object\":{},\"array\":[],\"null\":null,\"emptyArray\":[],\"emptyObject\":{},\"arrayString\":[\"alpha\",\"beta\"],\"arrayNum\":[1,212512.01,3],\"arrayBool\":[false,true,true],\"arrayNull\":[null,null],\"arrayObject\":[{\"firstName\":\"name1\",\"lastName\":\"name\"},{\"firstName\":\"name1\",\"lastName\":\"name\"},{\"firstName\":\"name2\",\"lastName\":\"name\"},{\"firstName\":\"name3\",\"lastName\":\"name1\"}],\"arrayArray\":[[null,false,5,\" - 0215.512501\",9.22337203685478E+18],[{},true,null,125651,\"simple\"],[{\"field\":null},\"hi\"]]}")]
        //[InlineData("{\"arrayString\":[\"alpha\",\"beta\"],\"arrayNum\":[1,212512.01,3],\"arrayBool\":[false,true,true],\"arrayNull\":[null,null]}")]
        //[InlineData("{\"arrayObject\":[{\"firstName\":\"name1\",\"lastName\":\"name\"},{\"firstName\":\"name1\",\"lastName\":\"name\"},{\"firstName\":\"name2\",\"lastName\":\"name\"},{\"firstName\":\"name3\",\"lastName\":\"name1\"}]}")]
        //[InlineData("{\"arrayArray\":[[null,false,5,\" - 0215.512501\",9.22337203685478E+18],[{},true,null,125651,\"simple\"],[{\"field\":null},\"hi\"]]}")]
        //[InlineData("{\"arrayArray\":[[{\"field\":null},\"hi\"]]}")]
        [MemberData(nameof(GetJsonObjects))]
        public void Parse_Valid(byte[] json, Dictionary<string, object> expected)
        {
            var value = JsonParser.Parse(json);

            AssertDictionaryEqual(expected, value);
        }

        private static void AssertDictionaryEqual(Dictionary<string, object> expected, Dictionary<string, object> value)
        {
            foreach (var expectedItem in expected)
            {
                if (!value.ContainsKey(expectedItem.Key))
                {
                    throw new Xunit.Sdk.AssertActualExpectedException(expected, value, $"Expected the key {expectedItem.Key}.");
                }

                var valueItem = value[expectedItem.Key];
                if (expectedItem.Value is Dictionary<string, object> expectedDict)
                {
                    if (!(valueItem is Dictionary<string, object> valueDict))
                    {
                        throw new Xunit.Sdk.AssertActualExpectedException(expected, value, $"Expected the type '{typeof(Dictionary<string, object>)}', got {valueItem?.GetType()}.");
                    }

                    AssertDictionaryEqual(expectedDict, valueDict);
                }
                else if (expectedItem.Value is List<object> expectedList)
                {
                    if (!(valueItem is List<object> valueList))
                    {
                        throw new Xunit.Sdk.AssertActualExpectedException(expected, value, $"Expected the type '{typeof(List<object>)}', got {valueItem?.GetType()}.");
                    }

                    AssertListEqual(expectedList, valueList);
                }
                else
                {
                    Assert.Equal(expectedItem.Value, valueItem);
                }
            }
        }

        private static void AssertListEqual(List<object> expected, List<object> value)
        {
            for (int i = 0; i < expected.Count; i++)
            {
                object expectedItem = expected[i];
                var valueItem = value[i];
                if (expectedItem is Dictionary<string, object> expectedDict)
                {
                    if (!(valueItem is Dictionary<string, object> valueDict))
                    {
                        throw new Xunit.Sdk.AssertActualExpectedException(expected, value, $"Expected the type '{typeof(Dictionary<string, object>)}', got {valueItem?.GetType()}.");
                    }

                    AssertDictionaryEqual(expectedDict, valueDict);
                }
                else if (expectedItem is List<object> expectedList)
                {
                    if (!(valueItem is List<object> valueList))
                    {
                        throw new Xunit.Sdk.AssertActualExpectedException(expected, value, $"Expected the type '{typeof(List<object>)}', got {valueItem?.GetType()}.");
                    }

                    AssertListEqual(expectedList, valueList);
                }
                else
                {
                    Assert.Equal(expectedItem, valueItem);
                }
            }
        }

        public static IEnumerable<object[]> GetJsonObjects()
        {
            yield return new object[] {
            Encoding.UTF8.GetBytes("{\"arrayArray\":[{\"field\":null}]}"),
                new Dictionary<string, object>
                {
                    {  "arrayArray", new List<object>
                        {
                                new Dictionary<string, object> { { "field", null } }
                        }
                    }
                }
            };

            //yield return new object[] {
            //    Encoding.UTF8.GetBytes("{\"arrayArray\":[[{\"field\":null},\"hi\"]]}"),
            //    new Dictionary<string, object>
            //    {
            //        {  "arrayArray", new List<object>
            //            {
            //                new List<object>
            //                {
            //                    new Dictionary<string, object> { { "field", null } },
            //                    "hi"
            //                }
            //            }
            //        }
            //    }
            //};
        }
    }
}
