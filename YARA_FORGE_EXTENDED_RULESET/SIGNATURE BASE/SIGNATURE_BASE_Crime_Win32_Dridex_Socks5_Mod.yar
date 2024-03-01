import "pe"

rule SIGNATURE_BASE_Crime_Win32_Dridex_Socks5_Mod
{
	meta:
		description = "Detects Dridex socks5 module"
		author = "@VK_Intel"
		id = "cee256b1-ad80-55dd-bbd3-0d3f7bc49664"
		date = "2020-04-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_evilcorp_dridex_banker.yar#L8-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5ca09e9c7d94e949e453d1bb69b566c12b253579cbcae700929d4f517df35a0a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "socks5_2_x32.dll"
		$s1 = "socks5_2_x64.dll"

	condition:
		any of ($s*) and pe.exports("start")
}
