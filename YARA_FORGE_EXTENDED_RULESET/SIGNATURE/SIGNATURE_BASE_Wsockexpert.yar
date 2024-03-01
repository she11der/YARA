rule SIGNATURE_BASE_Wsockexpert : FILE
{
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0ae115be-c516-5f4a-97ce-555d84f42947"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1123-L1141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
		logic_hash = "34ac3c5f0651ccab851d67da8863e0e305f981cf53a06d46c23f19736cc1c400"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2500KB and 4 of them
}
