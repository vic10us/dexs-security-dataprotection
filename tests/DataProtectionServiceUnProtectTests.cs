using System.Text;
using DEXS.Security.DataProtection.Tests.Models;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;

namespace DEXS.Security.DataProtection.Tests
{
    public class DataProtectionServiceUnProtectTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly IDataProtectionService _dataProtectionService;
        private readonly IDataProtectionServiceFactory _dataProtectionServiceFactory;

        public DataProtectionServiceUnProtectTests(ITestOutputHelper testOutputHelper, IDataProtectionServiceFactory dataProtectionServiceFactory)
        {
            _testOutputHelper = testOutputHelper;
            _dataProtectionServiceFactory = dataProtectionServiceFactory;
            _dataProtectionService = dataProtectionServiceFactory.CreateInstance("tests");
        }

        [Fact]
        public void CanUnprotectString()
        {
            var testResult = (string)TestData.TestResults["CanProtectString"];
            var x = _dataProtectionService.UnProtect(testResult);
            _testOutputHelper.WriteLine($"Unprotected: {x}");
            Assert.Equal("Test123", x);
        }

        [Fact]
        public void CanUnprotectObject()
        {
            var testResult = (string)TestData.TestResults["CanProtectObject"];
            // var testResult = "CfDJ8E+BPHCZOx5LnO1PsfR917dq8rpdtjptS2Fe90dTz8SEZbqu/y09hxTxOd4kjoBX9PSOBgXRo/EJ1FOb0iko2qBOgN0g7RgGByVHA/AI9NKlT3ety4RWR45Y1SJNQhwh7nt54dAaR/wnA/piYXfP+71tbrdkZLHtrix2mNz+ZxZM";
            var x = _dataProtectionService.UnProtectBase64String<object>(testResult);
            _testOutputHelper.WriteLine($"Unprotected: {JsonConvert.SerializeObject(x, Formatting.Indented)}");
            Assert.NotNull(x);
        }

        [Fact]
        public void CanUnProtectByteArray()
        {
            var testResult = (byte[])TestData.TestResults["CanProtectByteArray"];
            //var testResult = Convert.FromBase64String(
            //    "CfDJ8E+BPHCZOx5LnO1PsfR917d+nc9M/W1g59/XqkzMLZ2IL6GAcvteI69JuODRsihczcUFn1FuKL00tjVBtcHULNxYEuNmz9YXk9PokVz4REJdr5Uy4xYeE7/pA1g88cASJA==");
            var x = _dataProtectionService.UnProtect(testResult);
            var s = Encoding.UTF8.GetString(x);
            _testOutputHelper.WriteLine($"Unprotected [Test123] {s}");
            Assert.Equal("Test123", s);
        }

        [Fact]
        public void CanUnProtectStrongType()
        {
            var testResult = (byte[])TestData.TestResults["CanProtectStrongType"];
            //var testResult =
            //    Convert.FromBase64String("CfDJ8E+BPHCZOx5LnO1PsfR917eAK0kGqp8C0LFF53M7ykdlPoxEepgJ/rgxtaDuLgE0OTUrumrK7pmul7V3pMwfnnG2Ti0heBYZWIOIT9JOzec8FA05m2CmtyUo+HMA18wUSFOdBESy5fU/OGg0kX8o8MNHhn260eDq5i3o8Li5PK1K");
            var dec = _dataProtectionService.UnProtect<TestClass>(testResult);
            _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
        }

        [Fact]
        public void CanUnProtectScopedStrongType()
        {
            var testResult = (byte[])TestData.TestResults["CanProtectScopedStrongType"];
            //var testResult =
            //    Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAAHAQAAAAEBAAAAAwAAAAcCCQIAAAAJAwAAAAkEAAAADwIAAACEAAAAAgnwyfBPgTxwmTseS5ztT7H0fde3YcaV/VEezl4zCvmdx64TAcUl6Okuj60oMWom9bD/Fo1N3Oi+Y8hJbv+JH7w2+3v7kXlaBqJMzoGEPqDmYqW81oWPsnbMMKnbO2cDY+hTqNG31nwOW1Gy15FPh91aG0tXQiwZWZqHSjXD2qNUO77Jqg8DAAAAhAAAAAIJ8MnwT4E8cJk7Hkuc7U+x9H3Xt2bdtmNMS4hW+f18lOFrRcH4IN8jHxzAmY21QUjgDG2OJRbRQaOkWVCfPmdOUYs/cEjnne0pVvDFb9gz6ixltqPdeZGYDDboyuOWLMy4Gar5g4K3iBIutsdSRfDpkIZW8KlhB9Ky20GO1ba41A/hOGcPBAAAAIQAAAACCfDJ8E+BPHCZOx5LnO1PsfR917ed/AjnoMbOKUw2j6SRHWq6B+C4hQxcsXqx4dlgqBMjUTMVAgBycL3wbn+Il0QtHMme17/FXV3tRP+SSepcgelNwmQnpyZ4jp7p/nWIx/O5uR1pXe0/AAOW5cVb0iFctEEMmJ0IVau+VOxbmk+XH/SZCw==");
            var dps = _dataProtectionServiceFactory.CreateInstance("A", "B", "C");
            var dec = dps.UnProtectScoped<TestClass>(testResult);
            _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
        }

    }
}