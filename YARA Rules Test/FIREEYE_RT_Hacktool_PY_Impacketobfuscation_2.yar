rule FIREEYE_RT_Hacktool_PY_Impacketobfuscation_2
{
	meta:
		description = "wmiexec"
		author = "FireEye"
		id = "f1059f66-eaff-5866-bafb-c94236cf96a0"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/IMPACKETOBF (Wmiexec)/production/yara/HackTool_PY_ImpacketObfuscation_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "f3dd8aa567a01098a8a610529d892485"
		logic_hash = "ccbbe507798f16c7acf0780770fdb81b2e7dc333ab8bc51e6216816276c3f14b"
		score = 75
		quality = 75
		tags = ""
		rev = 2

	strings:
		$s1 = "import random"
		$s2 = "class WMIEXEC" nocase
		$s3 = "class RemoteShell" nocase
		$s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
		$s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase

	condition:
		all of them
}