using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;



Console.WriteLine("=====================================Protecting Data===================================");

// 1. It all begins by creating an instance of DataProtectionProvider
var provider = DataProtectionProvider.Create("AdvancedSecurityDataProtection");

// 2. Create a Protector
var protector = provider.CreateProtector("DataProtection");

// 3. Protect something
var sensitivePlainText = "Hello world!";
var protectedText = protector.Protect(sensitivePlainText);


Console.WriteLine($"Protected text: {protectedText}");

// unprotect the protected text
var unProtectedText = protector.Unprotect(protectedText);
Console.WriteLine($"Unprotected text: {unProtectedText}");