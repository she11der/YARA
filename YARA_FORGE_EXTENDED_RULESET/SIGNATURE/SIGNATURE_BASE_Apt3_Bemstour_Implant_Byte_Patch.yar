rule SIGNATURE_BASE_Apt3_Bemstour_Implant_Byte_Patch
{
	meta:
		description = "Detects an implant used by Bemstour exploitation tool (APT3)"
		author = "Mark Lechtik"
		id = "c30434c3-8949-566c-b6a6-29bffdaf961d"
		date = "2019-06-25"
		modified = "2023-12-04"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt3_bemstour.yar#L69-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"
		logic_hash = "08de2c885ccb24cb247efdcc06bbcbea144d652744b2d38aaa2aabfd341e4f91"
		score = 75
		quality = 85
		tags = ""
		company = "Check Point Software Technologies LTD."

	strings:
		$chunk_1 = {

C7 45 ?? 55 8B EC 83
C7 45 ?? EC 74 53 56
C7 45 ?? 8B 75 08 33
C7 45 ?? C9 57 C7 45
C7 45 ?? 8C 4C 6F 61

}

	condition:
		any of them
}