rule SIGNATURE_BASE_Cmdshell32 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f1dfb5a1-4292-5895-8310-913cfdf4d9d0"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L440-L455"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
		logic_hash = "cfe3d72d33d7a3c2b70d4fa0767a921c1cfcd360b2094af40b067789cace95af"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <62KB and all of them
}
