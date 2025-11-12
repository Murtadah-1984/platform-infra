namespace Identity.Domain.Entities;

/// <summary>
/// Join entity for many-to-many relationship between Role and Permission.
/// </summary>
public class RolePermission
{
    public Guid RoleId { get; set; }
    public Guid PermissionId { get; set; }
    
    // Navigation properties
    public Role Role { get; set; } = null!;
    public Permission Permission { get; set; } = null!;
}

