rule SIGNATURE_BASE_Fireball_Regkey : FILE
{
	meta:
		description = "Detects Fireball malware - file regkey.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6e22bb93-8c8b-510f-a9e4-6e57c392c2ae"
		date = "2017-06-02"
		modified = "2022-12-21"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_fireball.yar#L92-L108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f8fe8b1edb009ac84acf6159feada91d364507c53a9f92abd6b245b38fa058f5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"

	strings:
		$s1 = "\\WinMain\\Release\\WinMain.pdb" ascii
		$s2 = "ScreenShot" fullword wide
		$s3 = "WINMAIN" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
