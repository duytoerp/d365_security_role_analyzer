using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Đọc và kiểm tra chữ ký số Authenticode của file exe.</summary>
internal static class Authenticode
{
    /// <summary>Tên (subject) của chứng chỉ đã ký file, hoặc null nếu file chưa ký.</summary>
    public static string? SignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // Chỉ đọc chứng chỉ nhúng trong chữ ký, không nạp file chứng chỉ.
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>Chữ ký còn nguyên vẹn và chứng chỉ được Windows tin (WinVerifyTrust, không hiện giao diện).</summary>
    public static bool IsTrusted(string path)
    {
        var fileInfo = new WinTrustFileInfo { StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(), FilePath = path };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UIChoice = 2,       // WTD_UI_NONE
                RevocationChecks = 0, // WTD_REVOKE_NONE: không phụ thuộc mạng tới CRL
                UnionChoice = 1,    // WTD_CHOICE_FILE
                FileInfo = filePtr,
                StateAction = 0,    // WTD_STATEACTION_IGNORE
            };
            return WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref data) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(filePtr);
            Marshal.FreeHGlobal(filePtr);
        }
    }

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WinTrustData data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;
    }
}
