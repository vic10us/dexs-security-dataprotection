using System;
using System.Text;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;
using TestClass = DEXS.Security.DataProtection.Tests.Models.TestClass;

namespace DEXS.Security.DataProtection.Tests
{
    public class DataProtectionServiceProtectTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly IDataProtectionService _dataProtectionService;
        private readonly IDataProtectionServiceFactory _dataProtectionServiceFactory;

        public DataProtectionServiceProtectTests(ITestOutputHelper testOutputHelper, IDataProtectionServiceFactory dataProtectionServiceFactory)
        {
            _testOutputHelper = testOutputHelper;
            _dataProtectionServiceFactory = dataProtectionServiceFactory;
            _dataProtectionService = dataProtectionServiceFactory.CreateInstance("tests");
        }

        [Fact]
        public void CanProtectString()
        {
            var results = _dataProtectionService.Protect("Test123");
            TestData.TestResults.Add("CanProtectString", results);
            _testOutputHelper.WriteLine($"Test123 = {results}");
            Assert.NotNull(results);
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
            TestData.TestResults.Add("CanProtectObject", x);
            _testOutputHelper.WriteLine($"{JsonConvert.SerializeObject(o, Formatting.Indented)} = {x}");
            Assert.NotNull(x);
        }
        
        [Fact]
        public void CanProtectByteArray()
        {
            var x = _dataProtectionService.Protect(Encoding.UTF8.GetBytes("Test123"));
            TestData.TestResults.Add("CanProtectByteArray", x);
            _testOutputHelper.WriteLine($"Protected [Test123] {Convert.ToBase64String(x)}");
            Assert.NotNull(x);
        }

        [Fact]
        public void CanProtectStrongType()
        {
            var data = new TestClass
            {
                FirstName = "Kevin",
                LastName = "Smith"
            };
            var enc = _dataProtectionService.Protect<TestClass>(data);
            TestData.TestResults.Add("CanProtectStrongType", enc);
            _testOutputHelper.WriteLine($"Protected [TestClass] {Convert.ToBase64String(enc)}");
        }

        [Fact]
        public void CanProtectScopedStrongType()
        {
            var data = new TestClass
            {
                FirstName = "Kevin",
                LastName = "Smith"
            };
            var dps = _dataProtectionServiceFactory.CreateInstance("A", "B", "C");
            var dec = dps.ProtectScoped<TestClass>(data);
            TestData.TestResults.Add("CanProtectScopedStrongType", dec);
            _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
        }
    }
}
