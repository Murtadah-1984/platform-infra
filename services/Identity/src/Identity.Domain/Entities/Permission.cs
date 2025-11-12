namespace Identity.Domain.Entities;

/// <summary>
/// Permission entity for fine-grained access control.
/// </summary>
public class Permission
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Resource { get; set; } = string.Empty; // e.g., "payment", "identity"
    public string Action { get; set; } = string.Empty; // e.g., "read", "write", "admin"
    
    // Navigation properties
    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

