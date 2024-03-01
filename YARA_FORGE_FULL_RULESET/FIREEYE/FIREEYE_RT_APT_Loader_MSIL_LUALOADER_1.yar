rule FIREEYE_RT_APT_Loader_MSIL_LUALOADER_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "970a869e-bd69-5609-bb8d-77bfa78b0630"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/LUALOADER/production/yara/APT_Loader_MSIL_LUALOADER_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		logic_hash = "2d73d434ac39ebde990aca817a54208cd04bfbce33f1bcadcf48a50d9389658c"
		score = 75
		quality = 25
		tags = "FILE"

	strings:
		$sb1 = { 1? 72 [4] 14 D0 [2] 00 02 28 [2] 00 0A 1? 8D [2] 00 01 13 ?? 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 28 [2] 00 0A 28 [2] 00 0A 80 [2] 00 04 7E [2] 00 04 7B [2] 00 0A 7E [2] 00 04 11 ?? 11 ?? 6F [2] 00 0A 6F [2] 00 0A }
		$ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
		$ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
		$ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
		$ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
		$ss5 = "1F 8B 08 00 00 00 00 00" wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
