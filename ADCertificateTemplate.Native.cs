using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class CTNativeResultRc2 {
    public string Stage;
    public bool CloneAttempted, CloneReturned, SaveAttempted, SaveReturned;
    public string Error, NativeOID;
    public List<Dictionary<string,string>> Snapshots = new List<Dictionary<string,string>>();
}

public static class CTNativeBackendRc2 {
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern IntPtr ldap_initW(string host, uint port);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern uint ldap_set_optionW(IntPtr ld, int option, ref uint value);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern uint ldap_bind_sW(IntPtr ld, string dn, IntPtr credentials, uint method);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",ExactSpelling=true)]
    static extern uint ldap_unbind(IntPtr ld);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CAFindCertTypeByName(string name, IntPtr scope, uint flags, out IntPtr certType);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CACloneCertType(IntPtr source, string name, string displayName, IntPtr ldap, uint flags, out IntPtr clone);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CADCSetCertTypePropertyEx(IntPtr certType, string name, IntPtr value, IntPtr ldap);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true,EntryPoint="CAGetCertTypePropertyEx")]
    static extern int GetDword(IntPtr certType, string name, out uint value);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true,EntryPoint="CAGetCertTypePropertyEx")]
    static extern int GetStringArray(IntPtr certType, string name, out IntPtr values);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAFreeCertTypeProperty(IntPtr certType, IntPtr values);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeFlagsEx(IntPtr certType, uint option, uint flags);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAGetCertTypeFlagsEx(IntPtr certType, uint option, out uint flags);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeKeySpec(IntPtr certType, uint spec);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAUpdateCertTypeEx(IntPtr ldap, uint flags, IntPtr certType);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CACloseCertType(IntPtr certType);

    static void Check(int hr, string operation) {
        if (hr != 0) throw new COMException(operation+" returned 0x"+unchecked((uint)hr).ToString("X8"),hr);
    }
    static void LdapCheck(uint code, string operation) {
        if (code != 0) throw new InvalidOperationException(operation+" returned LDAP code "+code);
    }
    static string UIntText(IntPtr h, string name) {
        uint value; int hr=GetDword(h,name,out value);
        return hr==0 ? value.ToString() : "Unavailable:0x"+unchecked((uint)hr).ToString("X8");
    }
    static string Strings(IntPtr h, string name) {
        IntPtr values=IntPtr.Zero;
        try {
            int hr=GetStringArray(h,name,out values);
            if (hr!=0) return "Unavailable:0x"+unchecked((uint)hr).ToString("X8");
            var items=new List<string>();
            if (values!=IntPtr.Zero) for (int i=0;i<128;i++) {
                IntPtr item=Marshal.ReadIntPtr(values,i*IntPtr.Size);
                if (item==IntPtr.Zero) return String.Join("|",items.ToArray());
                items.Add(Marshal.PtrToStringUni(item));
            }
            if (values!=IntPtr.Zero) throw new InvalidOperationException("Unterminated native string array");
            return "";
        } finally { if (values!=IntPtr.Zero) CAFreeCertTypeProperty(h,values); }
    }
    static void SetUInt(IntPtr h,IntPtr ld,string name,uint value) {
        IntPtr p=Marshal.AllocHGlobal(4);
        try {Marshal.WriteInt32(p,unchecked((int)value));Check(CADCSetCertTypePropertyEx(h,name,p,ld),"Set "+name);}
        finally {Marshal.FreeHGlobal(p);}
    }
    static void SetStrings(IntPtr h,IntPtr ld,string name,params string[] values) {
        IntPtr array=Marshal.AllocHGlobal((values.Length+1)*IntPtr.Size);
        var allocated=new List<IntPtr>();
        try {
            for (int i=0;i<values.Length;i++) {
                IntPtr p=Marshal.StringToHGlobalUni(values[i]);allocated.Add(p);
                Marshal.WriteIntPtr(array,i*IntPtr.Size,p);
            }
            Marshal.WriteIntPtr(array,values.Length*IntPtr.Size,IntPtr.Zero);
            Check(CADCSetCertTypePropertyEx(h,name,array,ld),"Set "+name);
        } finally {foreach(IntPtr p in allocated) Marshal.FreeHGlobal(p);Marshal.FreeHGlobal(array);}
    }
    [StructLayout(LayoutKind.Sequential)]
    struct BitBlob { public uint Length; public IntPtr Data; public uint UnusedBits; }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CASetCertTypeExtension(IntPtr certType,string oid,uint flags,IntPtr extension);
    static void SetCertificateKeyUsage(IntPtr h,byte usage) {
        IntPtr data=Marshal.AllocHGlobal(1),blob=IntPtr.Zero;
        try {
            Marshal.WriteByte(data,usage);
            uint unused=0; int bit=usage;
            while ((bit&1)==0 && unused<7) {unused++;bit>>=1;}
            var b=new BitBlob {Length=1,Data=data,UnusedBits=unused};
            blob=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BitBlob)));
            Marshal.StructureToPtr(b,blob,false);
            Check(CASetCertTypeExtension(h,"2.5.29.15",1,blob),"Set certificate Key Usage");
        } finally {if(blob!=IntPtr.Zero) Marshal.FreeHGlobal(blob);Marshal.FreeHGlobal(data);}
    }
    static void Snapshot(CTNativeResultRc2 result,IntPtr h,string stage) {
        uint flags; int hr=CAGetCertTypeFlagsEx(h,3,out flags);
        result.Snapshots.Add(new Dictionary<string,string> {
            {"Stage",stage},{"Schema",UIntText(h,"msPKI-Template-Schema-Version")},
            {"KeySize",UIntText(h,"msPKI-Minimal-Key-Size")},
            {"Algorithm",Strings(h,"msPKI-Asymmetric-Algorithm")},
            {"Hash",Strings(h,"msPKI-Hash-Algorithm")},
            {"Flags",hr==0 ? "0x"+flags.ToString("X8") : "Unavailable"}
        });
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeExpiration(IntPtr h,ref long validity,ref long renewal);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CACertTypeSetSecurity(IntPtr h,byte[] security);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CADeleteCertTypeEx(IntPtr ld,uint flags,IntPtr h);

    static IntPtr Bind(string server) {
        IntPtr ld=ldap_initW(server,389);
        if(ld==IntPtr.Zero) throw new InvalidOperationException("ldap_initW failed");
        try {
            uint version=3,on=1;
            LdapCheck(ldap_set_optionW(ld,0x11,ref version),"LDAP version 3");
            LdapCheck(ldap_set_optionW(ld,0x95,ref on),"LDAP signing");
            LdapCheck(ldap_set_optionW(ld,0x96,ref on),"LDAP sealing");
            LdapCheck(ldap_bind_sW(ld,null,IntPtr.Zero,0x486),"LDAP Negotiate bind");
            return ld;
        } catch {ldap_unbind(ld);throw;}
    }
    // Read-only preparation. In particular: never clone during WhatIf.
    public static void Preflight(string server,string sourceOid) {
        IntPtr ld=IntPtr.Zero,h=IntPtr.Zero;
        try {
            ld=Bind(server);
            Check(CAFindCertTypeByName("WebServer",ld,0xCC0,out h),"Find native baseline");
            if(h==IntPtr.Zero || Strings(h,"msPKI-Cert-Template-OID")!=sourceOid)
                throw new InvalidOperationException("Native baseline OID differs from directory preflight");
        } finally {if(h!=IntPtr.Zero)CACloseCertType(h);if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
    static void SetKeyUsage(IntPtr h,byte[] usage) {
        if(usage==null || usage.Length<1 || usage.Length>2) throw new ArgumentException("Key Usage length");
        int length=usage.Length;
        while(length>1 && usage[length-1]==0)length--;
        int last=usage[length-1];
        if(last==0)throw new ArgumentException("Empty Key Usage");
        uint unused=0;while((last&1)==0){unused++;last>>=1;}
        IntPtr data=Marshal.AllocHGlobal(length),blob=IntPtr.Zero;
        try {
            Marshal.Copy(usage,0,data,length);
            var b=new BitBlob{Length=(uint)length,Data=data,UnusedBits=unused};
            blob=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BitBlob)));
            Marshal.StructureToPtr(b,blob,false);
            Check(CASetCertTypeExtension(h,"2.5.29.15",1,blob),"Set certificate Key Usage");
        } finally {if(blob!=IntPtr.Zero)Marshal.FreeHGlobal(blob);Marshal.FreeHGlobal(data);}
    }
    public static CTNativeResultRc2 Run(string server,string name,string displayName,string sourceOid,
        string algorithm,uint size,string hash,uint spec,uint usage,uint privateFlags,uint enrollmentFlags,
        uint subjectFlags,uint generalFlags,long validity,long renewal,byte[] certUsage,byte[] security,
        string[] providers,string[] ekus,string[] apps,string[] supersedes) {
        var r=new CTNativeResultRc2();
        IntPtr ld=IntPtr.Zero,source=IntPtr.Zero,clone=IntPtr.Zero;
        try {
            r.Stage="LdapBind";ld=Bind(server);
            r.Stage="FindWebServer";
            Check(CAFindCertTypeByName("WebServer",ld,0xCC0,out source),"Find baseline");
            if(source==IntPtr.Zero || Strings(source,"msPKI-Cert-Template-OID")!=sourceOid)
                throw new InvalidOperationException("Baseline OID mismatch");
            r.Stage="Clone";r.CloneAttempted=true;
            Check(CACloneCertType(source,name,displayName,ld,3,out clone),"Clone new template");
            r.CloneReturned=true;
            if(clone==IntPtr.Zero || clone==source)throw new InvalidOperationException("Invalid/aliased clone handle");
            r.NativeOID=Strings(clone,"msPKI-Cert-Template-OID");
            if(String.IsNullOrEmpty(r.NativeOID)||r.NativeOID==sourceOid||r.NativeOID.StartsWith("Unavailable:"))
                throw new InvalidOperationException("No distinct generated OID");
            Snapshot(r,clone,"AfterClone");
            // Deliberately make the provider transition before final crypto setters.
            r.Stage="LegacyCompatibility";
            Check(CASetCertTypeFlagsEx(clone,3,privateFlags|0x100),"Set temporary legacy-provider bit");
            r.Stage="Schema4";SetUInt(clone,ld,"msPKI-Template-Schema-Version",4);
            r.Stage="ProviderTransition";
            Check(CASetCertTypeFlagsEx(clone,3,privateFlags),"Transition to KSP before final crypto");
            Snapshot(r,clone,"AfterKspTransition");
            r.Stage="Configuration";
            Check(CASetCertTypeFlagsEx(clone,4,generalFlags&0xFFFF),"Set general flags");
            Check(CASetCertTypeFlagsEx(clone,2,subjectFlags),"Set subject flags");
            Check(CASetCertTypeFlagsEx(clone,1,enrollmentFlags),"Set enrollment flags");
            Check(CASetCertTypeExpiration(clone,ref validity,ref renewal),"Set validity and renewal");
            SetUInt(clone,ld,"msPKI-RA-Signature",0);
            SetStrings(clone,ld,"pKIExtendedKeyUsage",ekus);
            SetStrings(clone,ld,"msPKI-Certificate-Application-Policy",apps);
            SetStrings(clone,ld,"msPKI-Supersede-Templates",supersedes);
            SetStrings(clone,ld,"pKICriticalExtensions",new string[]{"2.5.29.15"});
            r.Stage="FinalCryptography";
            SetStrings(clone,ld,"pKIDefaultCSPs",providers);
            SetStrings(clone,ld,"msPKI-Asymmetric-Algorithm",algorithm);
            Check(CASetCertTypeKeySpec(clone,spec),"Set KeySpec");
            SetUInt(clone,ld,"msPKI-Minimal-Key-Size",size);
            SetStrings(clone,ld,"msPKI-Hash-Algorithm",hash);
            SetUInt(clone,ld,"msPKI-Key-Usage",usage);
            SetKeyUsage(clone,certUsage);
            r.Stage="Security";Check(CACertTypeSetSecurity(clone,security),"Set exact planned security descriptor");
            Snapshot(r,clone,"BeforeSave");
            if(UIntText(clone,"msPKI-Template-Schema-Version")!="4" ||
                UIntText(clone,"msPKI-Minimal-Key-Size")!=size.ToString() ||
                Strings(clone,"msPKI-Asymmetric-Algorithm")!=algorithm ||
                Strings(clone,"msPKI-Hash-Algorithm")!=hash)
                throw new InvalidOperationException("Native pre-save crypto mismatch");
            r.Stage="NativeSave";r.SaveAttempted=true;
            Check(CAUpdateCertTypeEx(ld,0x800,clone),"Save native template");r.SaveReturned=true;
            Snapshot(r,clone,"AfterSave");r.Stage="Completed";
        } catch(Exception e){r.Error=e.ToString();}
        finally {
            if(clone!=IntPtr.Zero&&clone!=source)CACloseCertType(clone);
            if(source!=IntPtr.Zero)CACloseCertType(source);
            if(ld!=IntPtr.Zero)ldap_unbind(ld);
        }
        return r;
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CAOIDDeleteEx(uint flags,IntPtr ld,string oid);
    // Called only after PowerShell rechecks owned GUID/USN and zero template references.
    public static void DeleteOwnedOid(string server,string oid) {
        IntPtr ld=IntPtr.Zero;
        try {ld=Bind(server);Check(CAOIDDeleteEx(0x800,ld,oid),"Delete owned OID registration");}
        finally {if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
    public static void DeleteOwned(string server,string name,string oid) {
        IntPtr ld=IntPtr.Zero,h=IntPtr.Zero;
        try {
            ld=Bind(server);Check(CAFindCertTypeByName(name,ld,0xCC0,out h),"Find owned template for deletion");
            if(h==IntPtr.Zero || Strings(h,"msPKI-Cert-Template-OID")!=oid)
                throw new InvalidOperationException("Native deletion identity mismatch");
            Check(CADeleteCertTypeEx(ld,0x800,h),"Delete owned template and OID");
        } finally {if(h!=IntPtr.Zero)CACloseCertType(h);if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
}
