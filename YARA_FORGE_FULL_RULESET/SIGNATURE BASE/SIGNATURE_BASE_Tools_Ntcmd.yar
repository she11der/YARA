rule SIGNATURE_BASE_Tools_Ntcmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "db3f28d6-dfe8-5c79-a11b-e31701e250d7"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1893-L1911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"
		logic_hash = "c2487306a0d82ab76a048c001361c25bcd61d0f7a57a3b22df1c70299f0a72ba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii
		$s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
		$s6 = "NTcmd>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and 2 of them
}
