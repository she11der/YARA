rule SIGNATURE_BASE_Pc_Xai : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dcf1b57b-3616-5198-bd57-18505fee91ae"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1567-L1586"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
		logic_hash = "80659fcf1721b20f459ac0480401bdf643c95b46118d03320bc6d4e4ee4b67f7"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
		$s2 = "%SystemRoot%\\System32\\" ascii
		$s3 = "%APPDATA%\\" ascii
		$s4 = "---- C.Rufus Security Team ----" fullword wide
		$s5 = "www.snzzkz.com" fullword wide
		$s6 = "%CommonProgramFiles%\\" ascii
		$s7 = "GetRand.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
