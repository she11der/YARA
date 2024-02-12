rule SIGNATURE_BASE_Zeus_Panda___FILE
{
	meta:
		description = "Detects ZEUS Panda Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "2786b1e0-37af-5595-a24b-56ef3cb928a7"
		date = "2017-08-04"
		modified = "2023-12-05"
		reference = "https://cyberwtf.files.wordpress.com/2017/07/panda-whitepaper.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_zeus_panda.yar#L11-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "63312763196259204dcee6b6c46ae1a16abeab0afabbce9e2e8413131856b04e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bd956b2e81731874995b9b92e20f75dbf67ac5f12f9daa194525e1b673c7f83c"

	strings:
		$x1 = "SER32.dll" fullword ascii
		$x2 = "/c start \"\" \"%s\"" fullword wide
		$x3 = "del /F \"%s\"" fullword ascii
		$s1 = "bcdfghklmnpqrstvwxz" fullword ascii
		$s2 = "=> -,0;" fullword ascii
		$s3 = "Yahoo! Slurp" fullword ascii
		$s4 = "ZTNHGET ^&" fullword ascii
		$s5 = "MSIE 9" fullword ascii
		$s6 = "%s%08x.%s" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (2 of ($x*) or 4 of them )
}