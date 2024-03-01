import "pe"

rule REVERSINGLABS_Cert_Blocklist_9272607Cfc982B782A5D36C4B78F5E7B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e3ad8f20-d12f-54e9-a6da-7aad28a10287"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7710-L7728"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b1d6f27fb513542589a5c9011e501a9d298282bba6882eac0fc7bf3e6ebb291"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rada SP Z o o" and (pe.signatures[i].serial=="00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b" or pe.signatures[i].serial=="92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b") and 1605139200<=pe.signatures[i].not_after)
}
