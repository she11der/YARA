rule SIGNATURE_BASE_HKTL_Meterpreter_Inmemory
{
	meta:
		description = "Detects Meterpreter in-memory"
		author = "netbiosX, Florian Roth"
		id = "29c3bb7e-4da8-5924-ada7-2f28d9352009"
		date = "2020-06-29"
		modified = "2023-04-21"
		reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_metasploit_payloads.yar#L341-L363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4b39dbcb276842a1306205cf2e51ce86b6d2aa21353d277df15f4ea3b3d97678"
		score = 85
		quality = 85
		tags = ""

	strings:
		$sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
		$sxs1 = "metsrv.x64.dll" ascii fullword
		$ss1 = "WS2_32.dll" ascii fullword
		$ss2 = "ReflectiveLoader" ascii fullword
		$fp1 = "SentinelOne" ascii wide
		$fp2 = "fortiESNAC" ascii wide
		$fp3 = "PSNMVHookMS" ascii wide

	condition:
		(1 of ($sx*) or 2 of ($s*)) and not 1 of ($fp*)
}