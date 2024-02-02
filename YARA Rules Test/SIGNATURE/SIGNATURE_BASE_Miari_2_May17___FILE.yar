rule SIGNATURE_BASE_Miari_2_May17___FILE
{
	meta:
		description = "Detects Mirai Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "1c2cc98d-8ca5-5055-8f86-7f85c046ccd9"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_mirai.yar#L80-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "138a7d0c5508f0168f09329e97f00d0aacef17297558338cd88a9dc3ddddfee3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
		hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"

	strings:
		$s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
		$s2 = "GET /g.php HTTP/1.1" fullword ascii
		$s3 = "https://%[^/]/%s" fullword ascii
		$s4 = "pass\" value=\"[^\"]*\"" fullword ascii
		$s5 = "jbeupq84v7.2y.net" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <5000KB and 2 of them )
}