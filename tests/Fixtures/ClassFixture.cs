using System.Collections.Generic;
using System.Text;

namespace DEXS.Security.DataProtection.Tests.Fixtures
{

    public class ClassFixture
    {
        public ClassFixture() { Count++; }

        public static int Count { get; private set; }
    }
}
