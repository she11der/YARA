rule SIGNATURE_BASE_Ce_Enfal_Cmstar_Debug_Msg : FILE
{
	meta:
		description = "Detects the static debug strings within CMSTAR"
		author = "rfalcone"
		id = "2c483f20-4fa8-5246-9dcb-8868db64b6e3"
		date = "2015-05-10"
		modified = "2023-12-05"
		reference = "http://goo.gl/JucrP9"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_cmstar.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9b9cc7e2a2481b0472721e6b87f1eba4faf2d419d1e2c115a91ab7e7e6fc7f7c"
		logic_hash = "31251b7ce33eb561aeb7405514df83dc1e00fdf184e3deeaa48505407d9567a0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$d1 = "EEE\x0d\x0a" fullword
		$d2 = "TKE\x0d\x0a" fullword
		$d3 = "VPE\x0d\x0a" fullword
		$d4 = "VPS\x0d\x0a" fullword
		$d5 = "WFSE\x0d\x0a" fullword
		$d6 = "WFSS\x0d\x0a" fullword
		$d7 = "CM**\x0d\x0a" fullword

	condition:
		uint16(0)==0x5a4d and all of ($d*)
}
