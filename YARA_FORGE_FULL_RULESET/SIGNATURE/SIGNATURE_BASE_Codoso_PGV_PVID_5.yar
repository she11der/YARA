rule SIGNATURE_BASE_Codoso_PGV_PVID_5 : FILE
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "0202d82c-c1f8-59f7-96b6-b21f21c1dc69"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L192-L208"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e248bada3ac46611bbe2cf1e1afee902191a2c1fb9611c4a052318e5e093b015"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

	strings:
		$s1 = "/c del %s >> NUL" fullword ascii
		$s2 = "%s%s.manifest" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
