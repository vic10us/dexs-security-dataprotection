using System;
using System.Text;
using DEXS.Security.DataProtection.Tests.Models;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;

[assembly: TestFramework("DEXS.Security.DataProtection.Tests.Startup", "DEXS.Security.DataProtection.Tests")]
namespace DEXS.Security.DataProtection.Tests
{
    public class DataProtectionServiceTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly IDataProtectionService _dataProtectionService;

        public DataProtectionServiceTests(ITestOutputHelper testOutputHelper, IDataProtectionServiceFactory dataProtectionServiceFactory)
        {
            _testOutputHelper = testOutputHelper;
            _dataProtectionService = dataProtectionServiceFactory.CreateInstance("tests");
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
                "CfDJ8E-BPHCZOx5LnO1PsfR917eQPBnuNyPquunH71BOnnK3XhiQfJkJEZro5ZPDJl4GpUXt_V0jPm6iS3a8RpQTbg4oeBJAobqL3EXZbsm5zs8UedynsDy1DnAJCE5r1iokjw");
            _testOutputHelper.WriteLine($"Unprotected: {x}");
            Assert.Equal("Test123", x);
        }
        
        [Fact]
        public void CanUnprotectObject()
        {
            var x = _dataProtectionService.UnProtectBase64String<object>(
                "CfDJ8E+BPHCZOx5LnO1PsfR917dq8rpdtjptS2Fe90dTz8SEZbqu/y09hxTxOd4kjoBX9PSOBgXRo/EJ1FOb0iko2qBOgN0g7RgGByVHA/AI9NKlT3ety4RWR45Y1SJNQhwh7nt54dAaR/wnA/piYXfP+71tbrdkZLHtrix2mNz+ZxZM");
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
                "CfDJ8E+BPHCZOx5LnO1PsfR917d+nc9M/W1g59/XqkzMLZ2IL6GAcvteI69JuODRsihczcUFn1FuKL00tjVBtcHULNxYEuNmz9YXk9PokVz4REJdr5Uy4xYeE7/pA1g88cASJA==");
            var x = _dataProtectionService.UnProtect(arr);
            var s = Encoding.UTF8.GetString(x);
            _testOutputHelper.WriteLine($"Unprotected [Test123] {s}");
            Assert.Equal("Test123", s);
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
            _testOutputHelper.WriteLine($"Protected [TestClass] {Convert.ToBase64String(enc)}");
        }

        [Fact]
        public void CanUnProtectStrongType()
        {
            var data =
                "CfDJ8E+BPHCZOx5LnO1PsfR917eAK0kGqp8C0LFF53M7ykdlPoxEepgJ/rgxtaDuLgE0OTUrumrK7pmul7V3pMwfnnG2Ti0heBYZWIOIT9JOzec8FA05m2CmtyUo+HMA18wUSFOdBESy5fU/OGg0kX8o8MNHhn260eDq5i3o8Li5PK1K";
            var dec = _dataProtectionService.UnProtect<TestClass>(Convert.FromBase64String(data));
            _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
        }

    }
}
