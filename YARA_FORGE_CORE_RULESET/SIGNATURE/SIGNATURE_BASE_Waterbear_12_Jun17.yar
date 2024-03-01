rule SIGNATURE_BASE_Waterbear_12_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "cc0a071c-c409-57a2-80c5-dd93ca7db339"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_waterbear.yar#L203-L217"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "343e6f36190372cd5599a84834edc3935d27a1e01aeab53c5765598b5b4071fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "15d9db2c90f56cd02be38e7088db8ec00fc603508ec888b4b85d60d970966585"

	strings:
		$s1 = "O_PROXY" fullword ascii
		$s2 = "XMODIFY" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
