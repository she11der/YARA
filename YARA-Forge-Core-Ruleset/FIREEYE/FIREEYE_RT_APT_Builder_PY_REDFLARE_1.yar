rule FIREEYE_RT_APT_Builder_PY_REDFLARE_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "3b5ad25d-ce66-572e-9a91-40a73b8fd447"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/REDFLARE/production/yara/APT_Builder_PY_REDFLARE_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "d0a830403e56ebaa4bfbe87dbfdee44f"
		logic_hash = "1948cadb7242eb69bffbc222802ce9c1af38d7a846da09b6343b1449fe054e42"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$1 = "LOAD_OFFSET_32 = 0x612"
		$2 = "LOAD_OFFSET_64 = 0x611"
		$3 = "class RC4:"
		$4 = "struct.pack('<Q' if is64b else '<L'"
		$5 = "stagerConfig['comms']['config']"
		$6 = "_x86.dll"
		$7 = "_x64.dll"

	condition:
		all of them and @1[1]<@2[1] and @2[1]<@3[1] and @3[1]<@4[1] and @4[1]<@5[1]
}