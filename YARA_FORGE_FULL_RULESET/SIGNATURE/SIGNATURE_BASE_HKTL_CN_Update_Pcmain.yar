rule SIGNATURE_BASE_HKTL_CN_Update_Pcmain : FILE
{
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "24c9ba6f-0772-59c9-8bea-3a8bf7823e4c"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "update_PcMain"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L832-L858"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
		logic_hash = "aa905379f65a8d964b921f2b74b61d94f97536466a7fc48f05c437d617cf35f6"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 4 of them
}
