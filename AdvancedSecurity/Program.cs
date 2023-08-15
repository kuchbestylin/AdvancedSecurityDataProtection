using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

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

