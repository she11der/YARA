rule FIREEYE_RT_APT_Hacktool_MSIL_PRAT_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
		author = "FireEye"
		id = "4a876eb0-ed2f-5ef2-a9b3-ba728b07c8c0"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_PRAT_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "d707f017b56b0a873f1edca085ad40fc70cb24e8c9844f377bc28871a941d0b4"
		score = 75
		quality = 67
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "7d1219fb-a954-49a7-96c9-df9e6429a8c7" ascii nocase wide
		$typelibguid1 = "bc1157c2-aa6d-46f8-8d73-068fc08a6706" ascii nocase wide
		$typelibguid2 = "c602fae2-b831-41e2-b5f8-d4df6e3255df" ascii nocase wide
		$typelibguid3 = "dfaa0b7d-6184-4a9a-9eeb-c08622d15801" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
