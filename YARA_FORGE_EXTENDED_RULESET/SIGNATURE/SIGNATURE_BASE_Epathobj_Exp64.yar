rule SIGNATURE_BASE_Epathobj_Exp64 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cb56bbdc-8afa-5b4b-b7df-942dd3d60366"
		date = "2015-06-13"
		modified = "2022-12-21"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2419-L2438"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
		logic_hash = "dc4073a7d319cffbbce7b3c7b7cf02b007839b72fe14ec1fbdcd3343d57cf7bf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and 2 of them
}
