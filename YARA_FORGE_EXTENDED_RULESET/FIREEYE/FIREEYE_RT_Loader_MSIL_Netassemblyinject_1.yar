rule FIREEYE_RT_Loader_MSIL_Netassemblyinject_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'NET-Assembly-Inject' project."
		author = "FireEye"
		id = "62a7dc4c-678b-5f13-9661-4679eafe1c72"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/NETASSEMBLYINJECT/production/yara/Loader_MSIL_NETAssemblyInject_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "9a43df9ee26a44f4db5c2d22fbc1a6c86c5af0c9d44a79c6627a4cc8cf31bb8d"
		score = 75
		quality = 69
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "af09c8c3-b271-4c6c-8f48-d5f0e1d1cac6" ascii nocase wide
		$typelibguid1 = "c5e56650-dfb0-4cd9-8d06-51defdad5da1" ascii nocase wide
		$typelibguid2 = "e8fa7329-8074-4675-9588-d73f88a8b5b6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
