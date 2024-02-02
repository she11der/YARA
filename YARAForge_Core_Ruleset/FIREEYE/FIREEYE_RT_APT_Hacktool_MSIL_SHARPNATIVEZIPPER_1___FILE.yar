rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPNATIVEZIPPER_1___FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
		author = "FireEye"
		id = "c48835a7-06fe-5b30-be4d-086d98dc7a21"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPNATIVEZIPPER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "fa54375b21abbb613e695f70a15233575fbe6e0536716544bb3b527f5e3ed8c6"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}