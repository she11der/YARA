rule SIGNATURE_BASE_Eternalrocks_Svchost : FILE
{
	meta:
		description = "Detects EternalRocks Malware - file taskhost.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c38d3faa-06a2-5f57-a917-91974941352f"
		date = "2017-05-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/stamparm/status/864865144748298242"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_eternalrocks.yar#L32-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "989df6d582949adbc4e0e2063c99d9ad83c367cedae1030dc23aade091216602"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"

	strings:
		$s1 = "WczTkaJphruMyBOQmGuNRtSNTLEs" fullword ascii
		$s2 = "svchost.taskhost.exe" fullword ascii
		$s3 = "ConfuserEx v" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 2 of them )
}
