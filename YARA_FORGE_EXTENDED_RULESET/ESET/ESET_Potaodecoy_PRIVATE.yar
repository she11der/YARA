private rule ESET_Potaodecoy_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "215f1821-f70d-547e-b261-335dc1300bf2"
		date = "2015-07-30"
		modified = "2015-07-30"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/potao/PotaoNew.yara#L32-L45"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "93cbe1d1545d1fb85b3218b68619e67a1dda80d5888d2685a04915b861dfce01"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4d 5a }
		$str1 = "eroqw11"
		$str2 = "2sfsdf"
		$str3 = "RtlDecompressBuffer"
		$wiki_str = "spanned more than 100 years and ruined three consecutive" wide
		$old_ver1 = {53 68 65 6C 6C 33 32 2E 64 6C 6C 00 64 61 66 73 72 00 00 00 64 61 66 73 72 00 00 00 64 6F 63 (00 | 78)}
		$old_ver2 = {6F 70 65 6E 00 00 00 00 64 6F 63 00 64 61 66 73 72 00 00 00 53 68 65 6C 6C 33 32 2E 64 6C 6C 00}

	condition:
		($mz at 0) and (( all of ($str*)) or any of ($old_ver*) or $wiki_str)
}
