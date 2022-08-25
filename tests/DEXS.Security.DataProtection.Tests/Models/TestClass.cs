namespace DEXS.Security.DataProtection.TestProject.Models;

public class TestClass
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
}

public class TestDataProvider
{
    public Dictionary<string, object> TestResults = new Dictionary<string, object>();

    public TestDataProvider()
    {

    }
}

public static class TestData
{
    public static Dictionary<string, object> TestResults = new Dictionary<string, object>();
}