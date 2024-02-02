rule SIGNATURE_BASE_Waterbear_7_Jun17___FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "4613df5b-495e-5738-9b7f-ac8ff586cd17"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_waterbear.yar#L108-L125"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6a760abca78e799b194864ad56457ccb0b05123307da6bfcad0c66da47f485a1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6891aa78524e442f4dda66dff51db9798e1f92e6fefcdf21eb870b05b0293134"

	strings:
		$s1 = "Bluthmon.exe" fullword wide
		$s2 = "Motomon.exe" fullword wide
		$s3 = "%d.%s%d%d%d" fullword ascii
		$s4 = "mywishes.hlp" fullword ascii
		$s5 = "filemon.rtf" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}