rule SIGNATURE_BASE_Msfpayloads_Msf_3
{
	meta:
		description = "Metasploit Payloads - file msf.psh"
		author = "Florian Roth (Nextron Systems)"
		id = "ad09167f-a12a-5f07-940b-df679fa8e6c0"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L79-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d1aeb97c19365f996dc1bc0fd6e01342878967be25d3e042158eba986af28b4a"
		score = 75
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"

	strings:
		$s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
		$s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
		$s3 = ".func]::VirtualAlloc(0,"
		$s4 = ".func+AllocationType]::Reserve -bOr [" ascii
		$s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
		$s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
		$s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
		$s8 = ".func]::CreateThread(0,0,$" fullword ascii
		$s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
		$s10 = "= [System.Convert]::FromBase64String(\"/" ascii
		$s11 = "{ $global:result = 3; return }" fullword ascii

	condition:
		4 of them
}
