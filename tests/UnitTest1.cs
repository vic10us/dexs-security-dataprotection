using System;
using System.Linq;
using System.Text;
using System.Xml.Serialization;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;

[assembly: TestFramework("DEXS.Security.DataProtection.Tests.Startup", "DEXS.Security.DataProtection.Tests")]
namespace DEXS.Security.DataProtection.Tests
{
    public class DataProtectionServiceTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly IDataProtectionServiceFactory _dataProtectionServiceFactory;
        private readonly IDataProtectionService _dataProtectionService;

        public DataProtectionServiceTests(ITestOutputHelper testOutputHelper, IDataProtectionServiceFactory dataProtectionServiceFactory)
        {
            _testOutputHelper = testOutputHelper;
            _dataProtectionServiceFactory = dataProtectionServiceFactory;
            _dataProtectionService = _dataProtectionServiceFactory.CreateInstance("tests");
        }

        [Fact]
        public void CanProtectString()
        {
            var x = _dataProtectionService.Protect("Test123");
            _testOutputHelper.WriteLine($"Test123 = {x}");
            Assert.NotNull(x);
        }

        [Fact]
        public void CanProtectObject()
        {
            var o = new
            {
                FirstName = "Kevin",
                LastName = "Smith"
            };
            var x = _dataProtectionService.ProtectToString(o);
            _testOutputHelper.WriteLine($"{JsonConvert.SerializeObject(o, Formatting.Indented)} = {x}");
            Assert.NotNull(x);
        }
        
        [Fact]
        public void CanUnprotectString()
        {
            var x = _dataProtectionService.UnProtect(
                "CfDJ8E-BPHCZOx5LnO1PsfR917ezgcCbdnci4e1bQq2ynmF1JyOqsKwoZ1Edudq42mElP_3ikLMOxnJjfKELKIhhP2NORyfY2t2ciB2yIENIoTVoHADhiXqiuuP6rDuAMIcuSg");
            _testOutputHelper.WriteLine($"Unprotected: {x}");
            Assert.Equal("Test123", x);
        }
        
        [Fact]
        public void CanUnprotectObject()
        {
            var x = _dataProtectionService.UnProtectBase64String<object>(
                "CfDJ8E+BPHCZOx5LnO1PsfR917eHgtll/yb9K8y0cCrdwIazhlA69UnmDQIeXp7d6eauIB6s4/vEAVUdDHX4cidBAsYZhgyD/urn3ZxgzdhaIyPE95xH6XQe99nK6JyF7s/8gQda2+Z+zlxBc1AZHhRJgZwqDh++8RsmEeLB2wm/UOh+");
            _testOutputHelper.WriteLine($"Unprotected: {JsonConvert.SerializeObject(x, Formatting.Indented)}");
            Assert.NotNull(x);
        }

        [Fact]
        public void CanProtectByteArray()
        {
            var x = _dataProtectionService.Protect(Encoding.UTF8.GetBytes("Test123"));
            _testOutputHelper.WriteLine($"Protected [Test123] {Convert.ToBase64String(x)}");
            Assert.NotNull(x);
        }

        [Fact]
        public void CanUnProtectByteArray()
        {
            var arr = Convert.FromBase64String(
                "CfDJ8E+BPHCZOx5LnO1PsfR917dCjdFJBqqshxPM+nZMRjGnYyYLPRWwwgF+56xnCgCf/XZoYfcaZ2VxRTh/QVQ9KGNOqfyo24N6nE/DRY0wbeF8T+Q5PC7joflFbcZV+N7b9g==");
            var x = _dataProtectionService.UnProtect(arr);
            var s = Encoding.UTF8.GetString(x);
            _testOutputHelper.WriteLine($"Unprotected [Test123] {s}");
            Assert.Equal("Test123", s);
        }

    }

    public class TestClass
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
