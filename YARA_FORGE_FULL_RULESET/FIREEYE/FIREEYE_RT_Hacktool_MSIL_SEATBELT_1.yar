rule FIREEYE_RT_Hacktool_MSIL_SEATBELT_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
		author = "FireEye"
		id = "46477f87-2458-5b8e-894a-9aa536a441ad"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/BELTALOWDA/production/yara/HackTool_MSIL_SEATBELT_1.yar#L4-L25"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "848837b83865f3854801be1f25cb9f4d"
		logic_hash = "4248e5561ef60e725c23efc89c899d6fc8be5bf2142f700fb70daecd72c30dd8"
		score = 75
		quality = 30
		tags = "FILE"
		rev = 3

	strings:
		$msil = "_CorExeMain" ascii wide
		$str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
		$str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
		$str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
		$str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
		$str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
		$str6 = "*[System/EventID={0}]" ascii nocase wide
		$str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
		$str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
		$str9 = "{0}" ascii nocase wide
		$str10 = "{0,-23}" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}
