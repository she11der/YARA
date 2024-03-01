rule FIREEYE_RT_Credtheft_MSIL_Adpasshunt_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
		author = "FireEye"
		id = "35fb8032-c73a-549f-9bd9-409f7050bdb0"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/ADPASSHUNT/production/yara/CredTheft_MSIL_ADPassHunt_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "6efb58cf54d1bb45c057efcfbbd68a93"
		logic_hash = "85c7c147d6bf5b7cb417ff2910a3e7ab3be5e8a3651758c07f8f0ed42b5964d8"
		score = 50
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide

	condition:
		uint16(0)==0x5A4D and $typelibguid
}
