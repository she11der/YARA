rule SIGNATURE_BASE_APT_CN_Group_Loader_Jan20_1
{
	meta:
		description = "Detects loaders used by Chinese groups"
		author = "Vitali Kremez"
		id = "c85ae499-4f76-56ff-877d-887e1a7fc077"
		date = "2020-02-01"
		modified = "2023-12-05"
		reference = "https://twitter.com/VK_Intel/status/1223411369367785472?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_winnti.yar#L266-L278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "30a180ada2390ca8df4bf7883624a5a176249622b4c34ce96931fe62b09ea8e3"
		score = 80
		quality = 85
		tags = ""

	strings:
		$xc1 = { 8B C3 C1 E3 10 C1 E8 10 03 D8 6B DB 77 83 C3 13 }

	condition:
		1 of them
}