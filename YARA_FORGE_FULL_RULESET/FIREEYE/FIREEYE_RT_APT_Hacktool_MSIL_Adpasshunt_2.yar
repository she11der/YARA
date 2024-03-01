rule FIREEYE_RT_APT_Hacktool_MSIL_Adpasshunt_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "a3b12fd7-e82d-5ef0-9125-7c069cd9bec4"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/ADPASSHUNT/production/yara/APT_HackTool_MSIL_ADPassHunt_2.yar#L4-L23"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "6efb58cf54d1bb45c057efcfbbd68a93"
		logic_hash = "e2dc7db1860eef04a569f007c32abd507dd588d1392613efbb31f42ca66ff735"
		score = 50
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "LDAP://" wide
		$s2 = "[GPP] Searching for passwords now..." wide
		$s3 = "Searching Group Policy Preferences (Get-GPPPasswords + Get-GPPAutologons)!" wide
		$s4 = "possibilities so far)..." wide
		$s5 = "\\groups.xml" wide
		$s6 = "Found interesting file:" wide
		$s7 = "\x00GetDirectories\x00"
		$s8 = "\x00DirectoryInfo\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
