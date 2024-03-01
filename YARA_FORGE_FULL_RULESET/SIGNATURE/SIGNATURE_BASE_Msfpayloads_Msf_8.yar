rule SIGNATURE_BASE_Msfpayloads_Msf_8
{
	meta:
		description = "Metasploit Payloads - file msf.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "54466663-12ef-5fa4-a13c-e80ddbc0f4f8"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L196-L215"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d2b26276843cdfef2d1458ee6c3e2ecea962d1cd42bc21b86ebd03599bebcbc6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"

	strings:
		$s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
		$s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
		$s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
		$s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
		$s5 = ".Length,0x1000),0x3000,0x40)" ascii
		$s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
		$s7 = "::memset([IntPtr]($" ascii

	condition:
		6 of them
}
