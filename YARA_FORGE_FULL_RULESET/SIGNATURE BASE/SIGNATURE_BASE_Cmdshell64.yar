rule SIGNATURE_BASE_Cmdshell64 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f4d69be7-f717-53f7-873e-86acbb309106"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1932-L1951"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
		logic_hash = "fd8010ab2ab51feed62475f840ffaeef92cf1266c139b8f669b7fa5ff646fdab"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 4 of them
}
