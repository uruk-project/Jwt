using System;

namespace ConsoleApplication1
{
    public class MagicNumberAttribute : Attribute
    {
        public MagicNumberAttribute(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }

    class MyClass
    {
        [MagicNumberAttribute("dir")]
        public const uint Dir = 7498084u;
    }
}