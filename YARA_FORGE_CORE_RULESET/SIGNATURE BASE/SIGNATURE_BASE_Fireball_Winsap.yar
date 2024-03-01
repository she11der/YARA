rule SIGNATURE_BASE_Fireball_Winsap : FILE
{
	meta:
		description = "Detects Fireball malware - file winsap.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "e68e7738-f325-5b73-9e61-4e2413b7b7be"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_fireball.yar#L110-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "de722d90d82f82faa5dfe5991c846e5c16deb919ae653b8f9fe4d1ad0384c41d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"

	strings:
		$s1 = "aHR0cDovL2" ascii
		$s2 = "%s\\svchost.exe -k %s" fullword wide
		$s3 = "\\SETUP.dll" wide
		$s4 = "WinSAP.dll" fullword ascii
		$s5 = "Error %u in WinHttpQueryDataAvailable." fullword ascii
		$s6 = "UPDATE OVERWRITE" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 4 of them )
}
