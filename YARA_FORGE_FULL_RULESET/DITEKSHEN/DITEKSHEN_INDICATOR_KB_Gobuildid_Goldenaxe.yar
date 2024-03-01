rule DITEKSHEN_INDICATOR_KB_Gobuildid_Goldenaxe : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "e734d5b4-2332-5b46-a05e-fb35134ea070"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L1564-L1573"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4ab9aeaa74530de4a62ddfa8d7e8607e455d0ba4330260037327bec6d8d7abab"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"BrJuyMRdiZ7pC9Cah0is/rbDB__hXWimivbSGiCLi/B35SPLQwHal3ccR2gXNx/hEmVzhJWWatsrKwnENh_\"" ascii
		$s2 = "Go build ID: \"5bgieaBe9PcZCZf23WFp/bCZ0AUHYlqQmX8GJASV6/fGxRLMDDYrTm1jcLMt8j/Wof3n5634bwiwLHFKHTn\"" ascii

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and 1 of them
}
