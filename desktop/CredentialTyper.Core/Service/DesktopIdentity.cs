using System.Security.Cryptography;
using CredentialTyper.Transport.Crypto;

namespace CredentialTyper.Core.Service;

/// <summary>
/// 桌面长期身份：一对 X25519 静态密钥。私钥用 DPAPI（CurrentUser）加密落盘，
/// 只有当前 Windows 用户能解开；公钥从私钥现算，不单独存。
/// </summary>
public sealed class DesktopIdentity
{
    public Dh.KeyPair Static { get; }

    private DesktopIdentity(Dh.KeyPair kp) => Static = kp;

    public static string DefaultDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CredentialTyper");

    public static DesktopIdentity LoadOrCreate(string? dir = null)
    {
        dir ??= DefaultDir;
        var path = Path.Combine(dir, "identity.bin");

        if (File.Exists(path))
        {
            var prot = File.ReadAllBytes(path);
            var priv = ProtectedData.Unprotect(prot, null, DataProtectionScope.CurrentUser);
            try
            {
                return new DesktopIdentity(Dh.FromPrivate(priv));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(priv);
            }
        }

        var kp = Dh.Generate();
        Directory.CreateDirectory(dir);
        var protectedPriv = ProtectedData.Protect(kp.Private, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(path, protectedPriv);
        return new DesktopIdentity(kp);
    }
}
