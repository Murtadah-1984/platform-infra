namespace Identity.Domain.Interfaces;

/// <summary>
/// Password hashing service interface following Dependency Inversion Principle.
/// </summary>
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hashedPassword);
}

