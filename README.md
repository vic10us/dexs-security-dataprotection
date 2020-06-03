# DEXS.Security.DataProtection

### DEXS.Security.DataProtection is used to protect and unprotect data for multi-tenant and multi-scopes.

DEXS.Security.DataProtection is comprised of two main building blocks: 
- **DataProtectionService**
- **DataProtectionServiceFactory**

Built on top of Microsoft's [ASP.NET Core Data Protection](https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/introduction) security libraries. Most of the hard parts of secure encryption, decryption and key management are taken care of by this library. 

What the DataProtectionService does is abstract the implementation with an easy set protect, unprotect functions that can even work with dynamic objects and byte streams on top of simple dependency injection, plugin configuration and built-in support for FileSystem or Redis for key storage. _(other key storage options are possible with a small amount of effort)_

> Sample configuration [FileSystem]
```json
{
  ...
  "DataProtection": {
    "KeyLifeTime": "14.00:00:00",
    "Type": "FileSystem",
    "ConnectionString": "Path=keys;"
  }
}
```

> Sample configuration [Redis]
```json
{
  ...
  "DataProtection": {
    "KeyLifeTime": "14.00:00:00",
    "Type": "Redis",
    "ConnectionString": "uri=localhost;keystore=DataProtection-Keys;"
  }
}
```

> IoC / Dependency injection Setup
```csharp
using DEXS.Security.DataProtection;

namespace DemoApp {

	public class Startup {
	
		public void ConfigureServices(IServiceCollection services) {
			services.AddDataProtectionServices(options => {
				Configuration.Bind("DataProtection", options);
			});
			services.AddTransient<IDataProtectionServiceFactory, DataProtectionServiceFactory>();
		}
		
	}
	
}
```
> Basic usage
```csharp
public DemoClass {
	private readonly IDataProtectionServiceFactory _dataProtectionServiceFactory;
	
	public DemoClass(IDataProtectionServiceFactory dataProtectionServiceFactory) {
		_dataProtectionServiceFactory = dataProtectionServiceFactory;
	}

	public string ProtectString(string unencrypted) {
		var service = _dataProtectionServiceFactory.CreateInstance("somescope");
		return service.Protect(unencrypted);
	}

	public string UnProtectString(string encrypted) {
		var service = _dataProtectionServiceFactory.CreateInstance("somescope");
		return service.UnProtect(encrypted);
	}
	
	public byte[] ProtectObject(SomeObject obj) {
		var service = _dataProtectionServiceFactory.CreateInstance("somescope");
		return service.Protect<SomeObject>(obj);
	}
	
	public SomeObject UnProtectObject(byte[] encrypted) {
		var service = _dataProtectionServiceFactory.CreateInstance("somescope");
		return service.UnProtect<SomeObject>(encrypted);
	}
}
```
