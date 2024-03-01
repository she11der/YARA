rule SIGNATURE_BASE_Dubseven_File_Set : FILE
{
	meta:
		description = "Searches for service files loading UP007"
		author = "Matt Brooks, @cmatthewbrooks"
		id = "5b0a9cb9-aeef-5508-8854-51ad846b22c5"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_between-hk-and-burma.yar#L1-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "af98ab901ca97a350aa837779d74208a780b1099e113cfa59bee2eb33690918e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
		$file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
		$file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
		$file4 = "\\Microsoft\\Internet Explorer\\main.dll"
		$file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
		$file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
		$file7 = "\\Microsoft\\Internet Explorer\\mon"
		$file8 = "\\Microsoft\\Internet Explorer\\runas.exe"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and 3 of ($file*)
}
