using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Text;

Console.WriteLine("=====================================Protecting Data===================================");

// 1. It all begins by creating an instance of DataProtectionProvider
var provider = DataProtectionProvider.Create("AdvancedSecurityDataProtection");

// 2. Create a Protector
var protector = provider.CreateProtector("DataProtection");

// 3. Protect something
var sensitivePlainText = "Protect Me";
var protectedText = protector.Protect(sensitivePlainText);


Console.WriteLine($"Protected text: {protectedText}");

// unprotect the protected text
var unProtectedText = protector.Unprotect(protectedText);
Console.WriteLine($"Unprotected text: {unProtectedText}");


Console.WriteLine("=====================================Password Hashing===================================");

string password = "Pa$$w0rd!@";

// Generate a Random Salt
byte[] salt = new byte[128];
using (var randomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator.Create())
{
    // This will fill the salt a cryptographically strong random sequence of values
    randomNumberGenerator.GetBytes(salt);
}

string hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
    password: password,
    salt: salt,
    prf: KeyDerivationPrf.HMACSHA1,
    iterationCount: 10000,
    numBytesRequested: 256 / 8
));

Console.WriteLine($"Original Password - {password}");
Console.WriteLine($"Hashed Password - {hashedPassword}");


Console.WriteLine("=================================TimeLimited Protected Data===================================");

var timeLimitedProvider = DataProtectionProvider.Create("AdvancedSecurityDataProtection");
var timeLimitedProtector = provider.CreateProtector("DataProtection").ToTimeLimitedDataProtector();

string text = "Protect Me";
Console.WriteLine($"Original Text - {text}");
var securedText = timeLimitedProtector.Protect(text, lifetime: TimeSpan.FromSeconds(10));
Console.WriteLine($"Protected Text - {securedText}");
var unsecuredText = timeLimitedProtector.Unprotect(securedText);
Console.WriteLine($"Un-Protected Text - {unsecuredText}");

// Lets wait until the time limit ends and then try to unprotect again. An exception is thrown
Thread.Sleep(10001);
try
{
    timeLimitedProtector.Unprotect(securedText);
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}


Console.WriteLine("=================================Unprotecting Data With Lost Keys===================================");
var serviceCollection = new ServiceCollection();
serviceCollection.AddDataProtection();
var services = serviceCollection.BuildServiceProvider();
var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
var dataProtector = dataProtectionProvider.CreateProtector("DataProtection.RevokedKeys");

var sensitiveText = "Protect Me";
Console.WriteLine($"Original text: {sensitiveText}");

var protectedPlainText = dataProtector.Protect(Encoding.UTF8.GetBytes(sensitiveText));
Console.WriteLine($"Protected text: {Convert.ToBase64String(protectedPlainText)}");

var unProtectedPlainText = dataProtector.Unprotect(protectedPlainText);
Console.WriteLine($"Unprotected text: {Encoding.UTF8.GetString(unProtectedPlainText)}");

// We will use a Key Manager to remove all the keys
var keyManagerService = services.GetRequiredService<IKeyManager>();
keyManagerService.RevokeAllKeys(DateTimeOffset.Now);


//Now, we will try to unprotect the text but since the key does not exist, it will fail
try
{
    var tryUnprotect = dataProtector.Unprotect(protectedPlainText);
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}

// But let now use the IPersistedDataProtector to unprotect the values without having the keys
try
{
    if (dataProtector is IPersistedDataProtector persistedDataProtector)
    {
        bool requiresMigration, wasRevoked;
        var unprotectedPayload = persistedDataProtector.DangerousUnprotect(
            protectedData: protectedPlainText,
            ignoreRevocationErrors: true,
            requiresMigration: out requiresMigration,
            wasRevoked: out wasRevoked);

        Console.WriteLine($"RequiresMigration - {requiresMigration}");
        Console.WriteLine($"WasRevoked - {wasRevoked}");
        Console.WriteLine($"Unprotected lost key Value - {Encoding.ASCII.GetString(unprotectedPayload)}");
    }
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}