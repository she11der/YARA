rule FIREEYE_RT_APT_Builder_PY_REDFLARE_2
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "1af407f5-6eb7-5be9-a3d9-cd0f7a5f2503"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/REDFLARE/production/yara/APT_Builder_PY_REDFLARE_2.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "4410e95de247d7f1ab649aa640ee86fb"
		logic_hash = "675390e944a95156ad33ca783c90fdea9610cdc2e8c5c53e0c0fa213149b4714"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$1 = "<510sxxII"
		$2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
		$3 = "parsePluginOutput"

	condition:
		all of them and #2==2
}