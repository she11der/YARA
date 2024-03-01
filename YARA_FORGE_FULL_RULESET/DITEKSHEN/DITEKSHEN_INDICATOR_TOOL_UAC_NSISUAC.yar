import "pe"

rule DITEKSHEN_INDICATOR_TOOL_UAC_NSISUAC : FILE
{
	meta:
		description = "Detects NSIS UAC plugin"
		author = "ditekSHen"
		id = "4a7c20f6-bf0e-55fb-a0b9-7b51e4af7cd3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L575-L587"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "48c0247c789328a0ff62816f5d6ecac7a0f2a3fe2cb95d99c0e7d988147f7137"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "HideCurrUserOpt" fullword wide
		$s2 = "/UAC:%X /NCRC%s" fullword wide
		$s3 = "2MyRunAsStrings" fullword wide
		$s4 = "CheckElevationEnabled" fullword ascii
		$s5 = "UAC.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
