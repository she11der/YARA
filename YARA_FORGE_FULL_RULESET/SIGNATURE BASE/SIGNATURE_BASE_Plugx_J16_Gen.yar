rule SIGNATURE_BASE_Plugx_J16_Gen : FILE
{
	meta:
		description = "Detects PlugX Malware samples from June 2016"
		author = "Florian Roth (Nextron Systems)"
		id = "13ef1e80-7090-5a1e-bca7-8d3de0dc2247"
		date = "2016-06-08"
		modified = "2023-12-05"
		reference = "VT Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_win_plugx.yar#L10-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3e988243663264b2647e098e36b83dd675141fa9765c9bd47c30f29bf176cd8f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "%WINDIR%\\SYSTEM32\\SERVICES.EXE" fullword wide
		$x2 = "\\\\.\\PIPE\\RUN_AS_USER(%d)" fullword wide
		$x3 = "LdrLoadShellcode" fullword ascii
		$x4 = "Protocol:[%4s], Host: [%s:%d], Proxy: [%d:%s:%d:%s:%s]" fullword ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" fullword wide
		$s2 = "%s\\msiexec.exe %d %d" fullword wide
		$s3 = "l%s\\sysprep\\CRYPTBASE.DLL" fullword wide
		$s4 = "%s\\msiexec.exe UAC" fullword wide
		$s5 = "CRYPTBASE.DLL" fullword wide
		$s6 = "%ALLUSERSPROFILE%\\SxS" fullword wide
		$s7 = "%s\\sysprep\\sysprep.exe" fullword wide
		$s8 = "\\\\.\\pipe\\a%d" fullword wide
		$s9 = "\\\\.\\pipe\\b%d" fullword wide
		$s10 = "EName:%s,EAddr:0x%p,ECode:0x%p,EAX:%p,EBX:%p,ECX:%p,EDX:%p,ESI:%p,EDI:%p,EBP:%p,ESP:%p,EIP:%p" fullword ascii
		$s11 = "Mozilla/4.0 (compatible; MSIE " fullword wide
		$s12 = "; Windows NT %d.%d" fullword wide
		$s13 = "SOFTWARE\\Microsoft\\Internet Explorer\\Version Vector" fullword wide
		$s14 = "\\bug.log" wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 4 of ($s*))) or (8 of them )
}
