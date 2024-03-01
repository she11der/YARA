rule FIREEYE_RT_Hunting_Gadgettojscript_1
{
	meta:
		description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
		author = "FireEye"
		id = "76c932e0-55b3-56ef-bab6-eb6997b51ee7"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/G2JS/production/yara/Hunting_GadgetToJScript_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "7af24305a409a2b8f83ece27bb0f7900"
		logic_hash = "a880c20e61376dacd4e3a04f2cf065f19067c29371180b1dec186172cadf9564"
		score = 50
		quality = 75
		tags = ""
		rev = 4

	strings:
		$s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
		$s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
		$s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"

	condition:
		any of them
}
