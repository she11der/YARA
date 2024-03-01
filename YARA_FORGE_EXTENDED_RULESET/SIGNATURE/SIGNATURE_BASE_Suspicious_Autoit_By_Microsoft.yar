rule SIGNATURE_BASE_Suspicious_Autoit_By_Microsoft : FILE
{
	meta:
		description = "Detects a AutoIt script with Microsoft identification"
		author = "Florian Roth (Nextron Systems)"
		id = "69b1c93d-ab12-5fdc-b6eb-fb135796d3a9"
		date = "2017-12-14"
		modified = "2023-12-05"
		reference = "Internal Research - VT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/generic_anomalies.yar#L375-L390"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7dfbaf7d136bd9e151c533b49394a9a596450d9cc2643dc144cb693290004591"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"

	strings:
		$s1 = "Microsoft Corporation. All rights reserved" fullword wide
		$s2 = "AutoIt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
