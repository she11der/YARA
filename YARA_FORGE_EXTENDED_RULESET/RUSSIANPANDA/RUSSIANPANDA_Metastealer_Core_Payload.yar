import "pe"

rule RUSSIANPANDA_Metastealer_Core_Payload
{
	meta:
		description = "Detects MetaStealer Core Payload"
		author = "RussianPanda"
		id = "ff5854b5-4dac-59d7-8c5a-d5b808d63483"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/MetaStealer/metastealer_core_payload_12-2023.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "99a319023f2c1b714a70458bd33649d6cc343b500a409af12c2eb1ce38ba4241"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "FileScannerRule"
		$s2 = "TreeObject"
		$s3 = "Schema"
		$s4 = "StringDecrypt"
		$s5 = "AccountDetails"

	condition:
		4 of ($s*) and pe.imports("mscoree.dll")
}
