rule FIREEYE_RT_Builder_MSIL_Sharpgenerator_1___FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
		author = "FireEye"
		id = "ab661cba-f695-59d2-9071-9b9a90233457"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/SHARPGENERATOR/production/yara/Builder_MSIL_SharpGenerator_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "6dc0780e54d33df733aadc8a89077232baa63bf1cbe47c5d164c57ce3185dd71"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "3f450977-d796-4016-bb78-c9e91c6a0f08" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}