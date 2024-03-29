rule FIREEYE_RT_APT_Loader_MSIL_LUALOADER_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "f2826dbb-f0a4-5361-94d1-8509c60c4131"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/LUALOADER/production/yara/APT_Loader_MSIL_LUALOADER_2.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		logic_hash = "700927768669eda6976071306e991bfaae136279f4265980521597c699fbed88"
		score = 75
		quality = 25
		tags = "FILE"

	strings:
		$ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
		$ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
		$ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
		$ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
		$ss5 = "1F 8B 08 00 00 00 00 00" wide
		$ss6 = "\x00LoadLibrary\x00"
		$ss7 = "\x00GetProcAddress\x00"
		$ss8 = "\x00VirtualProtect\x00"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
