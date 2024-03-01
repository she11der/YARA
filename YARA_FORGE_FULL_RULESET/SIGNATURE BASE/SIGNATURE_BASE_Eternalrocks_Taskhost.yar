rule SIGNATURE_BASE_Eternalrocks_Taskhost : FILE
{
	meta:
		description = "Detects EternalRocks Malware - file taskhost.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8926cdf8-6a3c-5237-80f5-bda9efb39a32"
		date = "2017-05-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/stamparm/status/864865144748298242"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_eternalrocks.yar#L12-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "45e5295f34280078c586c4cb643dba65aed63beffb1d6ded05de03403caf273a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"

	strings:
		$x1 = "EternalRocks.exe" fullword wide
		$s1 = "sTargetIP" fullword ascii
		$s2 = "SERVER_2008R2_SP0" fullword ascii
		$s3 = "20D5CCEE9C91A1E61F72F46FA117B93FB006DB51" fullword ascii
		$s4 = "9EBF75119B8FC7733F77B06378F9E735D34664F6" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 1 of ($x*) or 3 of them )
}
