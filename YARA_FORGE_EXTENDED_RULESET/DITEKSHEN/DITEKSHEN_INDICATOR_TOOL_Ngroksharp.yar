import "pe"

rule DITEKSHEN_INDICATOR_TOOL_Ngroksharp : FILE
{
	meta:
		description = "Detects NgrokSharp .NET library for Ngrok"
		author = "ditekSHen"
		id = "7c335021-4afd-5878-83c3-9bb2c81f3586"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_tools.yar#L1455-L1471"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c60637177114d369af9c3e96689811845ce1c1dfde8f7f971c4de21439564b4b"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$x1 = "NgrokSharp" fullword wide
		$x2 = "/entvex/NgrokSharp" ascii
		$s1 = "start --none -region" wide
		$s2 = "startTunnelDto" fullword wide
		$s3 = "/tunnels/" fullword wide
		$s4 = "<StartNgrok" ascii
		$s5 = "INgrokManager" ascii
		$s6 = "_tunnel_name" ascii
		$s7 = "_ngrokDownloadUrl" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 4 of ($*))
}
