rule SIGNATURE_BASE_Msfpayloads_Msf_4
{
	meta:
		description = "Metasploit Payloads - file msf.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "00d7681b-6041-5fe1-adbb-8b7c40df0193"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L104-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8e84ef13aa72c7c35520b3534b908c7d00240915ab02f8216a2cef6440c322a2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"

	strings:
		$s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
		$s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
		$s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
		$s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
		$s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii

	condition:
		4 of them
}
