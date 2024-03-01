rule FIREEYE_RT_Credtheft_MSIL_Adpasshunt_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b6103e23-8d1c-5d01-b283-f4545ccb924e"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/ADPASSHUNT/production/yara/CredTheft_MSIL_ADPassHunt_2.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "6efb58cf54d1bb45c057efcfbbd68a93"
		logic_hash = "e7282905a8baeaeb8ec156171fbf2bc4ac811facb80959a88394f4938a145cc1"
		score = 50
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$pdb1 = "\\ADPassHunt\\"
		$pdb2 = "\\ADPassHunt.pdb"
		$s1 = "Usage: .\\ADPassHunt.exe"
		$s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
		$s3 = "[ADA] Searching for accounts with userpassword attribute"
		$s4 = "[GPP] Searching for passwords now"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and ((@pdb2[1]<@pdb1[1]+50) or 2 of ($s*))
}
