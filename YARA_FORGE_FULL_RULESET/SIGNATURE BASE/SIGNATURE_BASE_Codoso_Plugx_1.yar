rule SIGNATURE_BASE_Codoso_Plugx_1 : FILE
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "af777818-5cff-5571-b5e9-0f5a4c8b08ff"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L276-L294"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "34736c85699a94b1413e5f9934e1a55841e8296df61d558bccf2d477e545d156"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
		hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
		hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"

	strings:
		$s1 = "GETPASSWORD1" fullword ascii
		$s2 = "NvSmartMax.dll" fullword ascii
		$s3 = "LICENSEDLG" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
