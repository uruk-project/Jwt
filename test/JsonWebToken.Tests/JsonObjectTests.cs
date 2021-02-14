using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonObjectTests
    {
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [Theory]
        public void AddReplacesExistingMember(int initialMemberCount)
        {
            JsonObject o = new JsonObject();
            for( int i = 0; i<initialMemberCount;++i)
            {
                o.Add(i.ToString(), "Padding");
            }
            o.Add("A", true);
            Assert.True(o.TryGetValue("A", out var vT));
            Assert.True((bool)vT.Value);
            Assert.Equal(initialMemberCount + 1, o.Count);

            o.Add("A", false);
            Assert.True(o.TryGetValue("A", out var vF) && vF.Value.Equals(false));
            Assert.True(o.Count == initialMemberCount + 1);
        }
    }
}
