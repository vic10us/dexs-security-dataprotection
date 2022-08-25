namespace DEXS.Security.DataProtection.TestProject;

[TestCaseOrderer("Xunit.Microsoft.DependencyInjection.TestsOrder.TestPriorityOrderer", "Xunit.Microsoft.DependencyInjection")]
public class DataProtectionServiceProtectTests : TestBed<TestFixture>
{
    private readonly IDataProtectionService _dataProtectionService;
    private readonly TestDataProvider _testData;
    private readonly IDataProtectionServiceFactory _dataProtectionServiceFactory;

    public DataProtectionServiceProtectTests(ITestOutputHelper testOutputHelper, TestFixture fixture) : base(testOutputHelper, fixture)
    {
        _dataProtectionServiceFactory = _fixture.GetService<IDataProtectionServiceFactory>(_testOutputHelper);
        _dataProtectionService = _dataProtectionServiceFactory.CreateInstance("tests");
        _testData = _fixture.GetService<TestDataProvider>(_testOutputHelper);
    }

    [Fact, TestOrder(1)]
    public void CanProtectString()
    {
        var results = _dataProtectionService.Protect("Test123");
        _testData.TestResults.Add("CanProtectString", results);
        _testOutputHelper.WriteLine($"Test123 = {results}");
        Assert.NotNull(results);
    }

    [Fact, TestOrder(2)]
    public void CanProtectObject()
    {
        var o = new
        {
            FirstName = "Kevin",
            LastName = "Smith"
        };
        var x = _dataProtectionService.ProtectToString(o);
        _testData.TestResults.Add("CanProtectObject", x);
        _testOutputHelper.WriteLine($"{JsonConvert.SerializeObject(o, Formatting.Indented)} = {x}");
        Assert.NotNull(x);
    }
    
    [Fact, TestOrder(3)]
    public void CanProtectByteArray()
    {
        var x = _dataProtectionService.Protect(Encoding.UTF8.GetBytes("Test123"));
        _testData.TestResults.Add("CanProtectByteArray", x);
        _testOutputHelper.WriteLine($"Protected [Test123] {Convert.ToBase64String(x)}");
        Assert.NotNull(x);
    }

    [Fact, TestOrder(4)]
    public void CanProtectStrongType()
    {
        var data = new TestClass
        {
            FirstName = "Kevin",
            LastName = "Smith"
        };
        var enc = _dataProtectionService.Protect<TestClass>(data);
        _testData.TestResults.Add("CanProtectStrongType", enc);
        _testOutputHelper.WriteLine($"Protected [TestClass] {Convert.ToBase64String(enc)}");
    }

    [Fact, TestOrder(5)]
    public void CanProtectScopedStrongType()
    {
        var data = new TestClass
        {
            FirstName = "Kevin",
            LastName = "Smith"
        };
        var dps = _dataProtectionServiceFactory.CreateInstance("A", "B", "C");
        var dec = dps.ProtectScoped<TestClass>(data);
        _testData.TestResults.Add("CanProtectScopedStrongType", dec);
        _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
    }

    [Fact, TestOrder(10)]
    public void CanUnprotectString()
    {
        var testResult = (string)_testData.TestResults["CanProtectString"];
        var x = _dataProtectionService.UnProtect(testResult);
        _testOutputHelper.WriteLine($"Unprotected: {x}");
        Assert.Equal("Test123", x);
    }

    [Fact, TestOrder(11)]
    public void CanUnprotectObject()
    {
        var testResult = (string)_testData.TestResults["CanProtectObject"];
        // var testResult = "CfDJ8E+BPHCZOx5LnO1PsfR917dq8rpdtjptS2Fe90dTz8SEZbqu/y09hxTxOd4kjoBX9PSOBgXRo/EJ1FOb0iko2qBOgN0g7RgGByVHA/AI9NKlT3ety4RWR45Y1SJNQhwh7nt54dAaR/wnA/piYXfP+71tbrdkZLHtrix2mNz+ZxZM";
        var x = _dataProtectionService.UnProtectBase64String<object>(testResult);
        _testOutputHelper.WriteLine($"Unprotected: {JsonConvert.SerializeObject(x, Formatting.Indented)}");
        Assert.NotNull(x);
    }

    [Fact, TestOrder(12)]
    public void CanUnProtectByteArray()
    {
        var testResult = (byte[])_testData.TestResults["CanProtectByteArray"];
        //var testResult = Convert.FromBase64String(
        //    "CfDJ8E+BPHCZOx5LnO1PsfR917d+nc9M/W1g59/XqkzMLZ2IL6GAcvteI69JuODRsihczcUFn1FuKL00tjVBtcHULNxYEuNmz9YXk9PokVz4REJdr5Uy4xYeE7/pA1g88cASJA==");
        var x = _dataProtectionService.UnProtect(testResult);
        var s = Encoding.UTF8.GetString(x);
        _testOutputHelper.WriteLine($"Unprotected [Test123] {s}");
        Assert.Equal("Test123", s);
    }

    [Fact, TestOrder(13)]
    public void CanUnProtectStrongType()
    {
        var testResult = (byte[])_testData.TestResults["CanProtectStrongType"];
        //var testResult =
        //    Convert.FromBase64String("CfDJ8E+BPHCZOx5LnO1PsfR917eAK0kGqp8C0LFF53M7ykdlPoxEepgJ/rgxtaDuLgE0OTUrumrK7pmul7V3pMwfnnG2Ti0heBYZWIOIT9JOzec8FA05m2CmtyUo+HMA18wUSFOdBESy5fU/OGg0kX8o8MNHhn260eDq5i3o8Li5PK1K");
        var dec = _dataProtectionService.UnProtect<TestClass>(testResult);
        _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
    }

    [Fact, TestOrder(14)]
    public void CanUnProtectScopedStrongType()
    {
        var testResult = (byte[])_testData.TestResults["CanProtectScopedStrongType"];
        //var testResult =
        //    Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAAHAQAAAAEBAAAAAwAAAAcCCQIAAAAJAwAAAAkEAAAADwIAAACEAAAAAgnwyfBPgTxwmTseS5ztT7H0fde3YcaV/VEezl4zCvmdx64TAcUl6Okuj60oMWom9bD/Fo1N3Oi+Y8hJbv+JH7w2+3v7kXlaBqJMzoGEPqDmYqW81oWPsnbMMKnbO2cDY+hTqNG31nwOW1Gy15FPh91aG0tXQiwZWZqHSjXD2qNUO77Jqg8DAAAAhAAAAAIJ8MnwT4E8cJk7Hkuc7U+x9H3Xt2bdtmNMS4hW+f18lOFrRcH4IN8jHxzAmY21QUjgDG2OJRbRQaOkWVCfPmdOUYs/cEjnne0pVvDFb9gz6ixltqPdeZGYDDboyuOWLMy4Gar5g4K3iBIutsdSRfDpkIZW8KlhB9Ky20GO1ba41A/hOGcPBAAAAIQAAAACCfDJ8E+BPHCZOx5LnO1PsfR917ed/AjnoMbOKUw2j6SRHWq6B+C4hQxcsXqx4dlgqBMjUTMVAgBycL3wbn+Il0QtHMme17/FXV3tRP+SSepcgelNwmQnpyZ4jp7p/nWIx/O5uR1pXe0/AAOW5cVb0iFctEEMmJ0IVau+VOxbmk+XH/SZCw==");
        var dps = _dataProtectionServiceFactory.CreateInstance("A", "B", "C");
        var dec = dps.UnProtectScoped<TestClass>(testResult);
        _testOutputHelper.WriteLine($"UnProtected [TestClass] {JsonConvert.SerializeObject(dec)}");
    }
}
