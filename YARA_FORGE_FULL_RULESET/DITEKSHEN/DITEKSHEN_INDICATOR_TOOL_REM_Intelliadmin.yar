import "pe"

rule DITEKSHEN_INDICATOR_TOOL_REM_Intelliadmin : FILE
{
	meta:
		description = "Detects commerical IntelliAdmin remote tool"
		author = "ditekSHen"
		id = "15385e0b-ead4-5614-a04e-55878eb70b34"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L589-L602"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8b601d68eff65bc6cc2fb46630a7021e229764f9a80f6d3278ba3b9f55e5b114"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$pdb1 = "\\Network Administrator" ascii
		$pdb2 = "\\Binaries\\Plugins\\Tools\\RPCService.pdb" ascii
		$s1 = "CIntelliAdminRPC" fullword wide
		$s2 = "IntelliAdmin RPC Service" fullword wide
		$s3 = "IntelliAdmin Remote Execute v" ascii
		$s4 = "IntelliAdminRPC" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($pdb*) or 2 of ($s*))
}
