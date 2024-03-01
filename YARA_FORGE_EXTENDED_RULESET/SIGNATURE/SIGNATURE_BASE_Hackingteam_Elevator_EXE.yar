rule SIGNATURE_BASE_Hackingteam_Elevator_EXE : FILE
{
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a68b68dd-372d-5572-a1e7-1b7e06e986d8"
		date = "2015-07-07"
		modified = "2023-12-05"
		reference = "Hacking Team Disclosure elevator.c"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hackingteam_rules.yar#L58-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"
		logic_hash = "58f3c28fa69da0329a4cd5451a86260056076a9d0094965e9c23a63ef72cfc98"
		score = 70
		quality = 81
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
		hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"

	strings:
		$x1 = "CRTDLL.DLL" fullword ascii
		$x2 = "\\sysnative\\CI.dll" ascii
		$x3 = "\\SystemRoot\\system32\\CI.dll" ascii
		$x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii
		$s1 = "[*] traversing processes" fullword ascii
		$s2 = "_getkprocess" fullword ascii
		$s3 = "[*] LoaderConfig %p" fullword ascii
		$s4 = "loader.obj" fullword ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii
		$s6 = "[*] token restore" fullword ascii
		$s7 = "elevator.obj" fullword ascii
		$s8 = "_getexport" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of ($x*) and 3 of ($s*)
}
