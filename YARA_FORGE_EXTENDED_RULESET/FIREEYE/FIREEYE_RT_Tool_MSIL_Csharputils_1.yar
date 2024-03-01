rule FIREEYE_RT_Tool_MSIL_Csharputils_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
		author = "FireEye"
		id = "a0e8c45a-759a-5611-aa2a-3113a75fb651"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/SHARPUTILS/production/yara/Tool_MSIL_CSharpUtils_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "11dfd44fb4ee1e610c2e4a941b3a1e88eafc30a2a2237529150e73bceb2a1324"
		score = 75
		quality = 65
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "2130bcd9-7dd8-4565-8414-323ec533448d" ascii nocase wide
		$typelibguid1 = "319228f0-2c55-4ce1-ae87-9e21d7db1e40" ascii nocase wide
		$typelibguid2 = "4471fef9-84f5-4ddd-bc0c-31f2f3e0db9e" ascii nocase wide
		$typelibguid3 = "5c3bf9db-1167-4ef7-b04c-1d90a094f5c3" ascii nocase wide
		$typelibguid4 = "ea383a0f-81d5-4fa8-8c57-a950da17e031" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
