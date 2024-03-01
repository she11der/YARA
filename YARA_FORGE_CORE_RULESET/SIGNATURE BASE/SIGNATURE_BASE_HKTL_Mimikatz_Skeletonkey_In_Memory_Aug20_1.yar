import "pe"

rule SIGNATURE_BASE_HKTL_Mimikatz_Skeletonkey_In_Memory_Aug20_1
{
	meta:
		description = "Detects Mimikatz SkeletonKey in Memory"
		author = "Florian Roth (Nextron Systems)"
		id = "e7c1c512-e944-5d87-ac57-cdc9ab7cf660"
		date = "2020-08-09"
		modified = "2023-12-05"
		reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mimikatz.yar#L178-L190"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0cc9a4d3b63e07a695df342bd2c96a55570502d6fd0ab9a1b61d63e28e1c3e05"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }

	condition:
		1 of them
}
