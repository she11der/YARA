rule SIGNATURE_BASE_SUSP_INDICATOR_RTF_Malver_Objects : CVE_2017_11882 FILE
{
	meta:
		description = "Detects RTF documents with non-standard version and embedding one of the object mostly observed in exploit (e.g. CVE-2017-11882) documents."
		author = "ditekSHen"
		id = "2d9d80e0-473e-5aac-a576-8f0002e120e2"
		date = "2022-10-20"
		modified = "2023-12-05"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_rtf_malver_objects.yar#L12-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "69136fb8ba180f6f86e569471bcefe8f55c61af73c66ebd6062ba7369aee9a72"
		score = 65
		quality = 85
		tags = "CVE-2017-11882, FILE"
		hash1 = "43812ca7f583e40b3e3e92ae90a7e935c87108fa863702aa9623c6b7dc3697a2"
		hash2 = "a31da6c6a8a340901f764586a28bd5f11f6d2a60a38bf60acd844c906a0d44b1"

	strings:
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and (( not uint8(4)==0x66 or not uint8(5)==0x31 or not uint8(6)==0x5c) and 1 of ($obj*))
}
