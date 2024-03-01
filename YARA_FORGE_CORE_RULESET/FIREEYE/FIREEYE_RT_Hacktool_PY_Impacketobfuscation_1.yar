rule FIREEYE_RT_Hacktool_PY_Impacketobfuscation_1
{
	meta:
		description = "smbexec"
		author = "FireEye"
		id = "992d1132-3136-5e1b-a1ef-dcdf36ebf0f5"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/IMPACKETOBF (Smbexec)/production/yara/HackTool_PY_ImpacketObfuscation_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "0b1e512afe24c31531d6db6b47bac8ee"
		logic_hash = "45a4c0426b29b8c8bede9c4e8292131da7e756d48fc3ac4a07d08fd52383d21e"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$s1 = "class CMDEXEC" nocase
		$s2 = "class RemoteShell" nocase
		$s3 = "self.services_names"
		$s4 = "import random"
		$s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
		$s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/

	condition:
		all of them
}
