rule FIREEYE_RT_Trojan_Macro_RESUMEPLEASE_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "068662f6-28b8-5538-8bc3-6506565305ae"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/RESUMEPLEASE/production/yara/Trojan_Macro_RESUMEPLEASE_1.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "d5d3d23c8573d999f1c48d3e211b1066"
		logic_hash = "040457bc446e496431129ff4623ddda5d9c2ce339ba65a7fbe42114626f36c60"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$str00 = "For Binary As"
		$str01 = "Range.Text"
		$str02 = "Environ("
		$str03 = "CByte("
		$str04 = ".SpawnInstance_"
		$str05 = ".Create("

	condition:
		all of them
}