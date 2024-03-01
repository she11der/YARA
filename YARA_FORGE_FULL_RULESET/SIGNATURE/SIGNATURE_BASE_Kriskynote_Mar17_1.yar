rule SIGNATURE_BASE_Kriskynote_Mar17_1 : FILE
{
	meta:
		description = "Detects Kriskynote Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b1e5df0c-0112-5fee-85e9-cb0ca31f5234"
		date = "2017-03-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_kriskynote.yar#L11-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cc4861f3a612cbaba6abf8ded76972941c879f04b59c29756bf0ba8083bf93ab"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a19c4b615aa54207604b181873e614d84126b639fee2cce3ca9d5bd863f6f577"
		hash2 = "62b41db0bf63fa45a2c2b0f5df8c2209a5d96bf2bddf82749595c66d30b7ec61"

	strings:
		$s1 = "gzwrite64" fullword ascii
		$opa1 = { e8 6b fd ff ff 83 f8 ff 74 65 83 7b 28 00 74 42 }
		$opb1 = { 8a 04 08 8b 8e a4 16 00 00 88 44 24 0c 66 c7 04 }
		$opb2 = { 89 4e 6c 89 46 74 e9 ad fc ff ff 8b 46 68 85 c0 }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and $s1 and ($opa1 or all of ($opb*))
}
