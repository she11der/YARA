rule FIREEYE_RT_Hacktool_MSIL_Sharpstomp_1___FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharpStomp project."
		author = "FireEye"
		id = "e113c221-fabe-5af4-b763-463c4f86288d"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/SHARPSTOMP/production/yara/HackTool_MSIL_SharpStomp_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "83ed748cd94576700268d35666bf3e01"
		logic_hash = "fd0a3d046734d48be74d9a74f27570468550d21911c54ca82c81a1d64e9fdd17"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid1 = "41f35e79-2034-496a-8c82-86443164ada2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}