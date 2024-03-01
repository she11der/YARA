rule FIREEYE_RT_APT_Hacktool_MSIL_GPOHUNT_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
		author = "FireEye"
		id = "e4325f11-103c-5893-8978-9a72f7ca6105"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/GPOHUNT/production/yara/APT_HackTool_MSIL_GPOHUNT_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "4b1f175dac123a6340494e2730d66c718478fb7618dc5611315992ed33e0f6c7"
		score = 50
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "751a9270-2de0-4c81-9e29-872cd6378303" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
