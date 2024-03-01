rule FIREEYE_RT_Hunting_B64Engine_Dotnettojscript_Dos
{
	meta:
		description = "This file may enclude a Base64 encoded .NET executable. This technique is used by the project DotNetToJScript which is used by many malware families including GadgetToJScript."
		author = "FireEye"
		id = "24c9c259-9bb9-5f46-9278-4fa20eb3c8c4"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/G2JS/production/yara/Hunting_B64Engine_DotNetToJScript_Dos.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "7af24305a409a2b8f83ece27bb0f7900"
		logic_hash = "e2afb43af469f8ae02f6fd21db6dbd45c997fb003e3aeeaa0d4ff3e85c64159a"
		score = 50
		quality = 75
		tags = ""
		rev = 1

	strings:
		$b64_mz = "AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEU"

	condition:
		$b64_mz
}
