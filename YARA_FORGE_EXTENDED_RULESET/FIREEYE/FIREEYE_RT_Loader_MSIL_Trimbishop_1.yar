rule FIREEYE_RT_Loader_MSIL_Trimbishop_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
		author = "FireEye"
		id = "4d58f0a2-bf16-584c-8e92-c8ef54427767"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/TRIMBISHOP/production/yara/Loader_MSIL_TrimBishop_1.yar#L4-L26"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "09bdbad8358b04994e2c04bb26a160ef"
		logic_hash = "018e87542301db22c384fda2709e8d49711c0fa041d1ef591f98ee7a70dbb677"
		score = 75
		quality = 50
		tags = "FILE"
		rev = 3

	strings:
		$msg = "msg" ascii wide
		$msil = "_CorExeMain" ascii wide
		$str1 = "RuralBishop" ascii wide
		$str2 = "KnightKingside" ascii wide
		$str3 = "ReadShellcode" ascii wide
		$str4 = "ReverseString" ascii wide
		$str5 = "DTrim" ascii wide
		$str6 = "QueensGambit" ascii wide
		$str7 = "Messages" ascii wide
		$str8 = "NtQueueApcThread" ascii wide
		$str9 = "NtAlertResumeThread" ascii wide
		$str10 = "NtQueryInformationThread" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and #msg>60 and all of ($str*)
}
