import "pe"

rule REVERSINGLABS_Cert_Blocklist_039E5D0E3297F574Db99E1D9503853D9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "969ffa17-de06-58d5-a74e-c115b49a9a6c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2824-L2840"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2f150f60b7dce583fc68705f0b29a7c8684f1b69020275b2ec1ac6beeaa63952"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cigam Software Corporativo LTDA" and pe.signatures[i].serial=="03:9e:5d:0e:32:97:f5:74:db:99:e1:d9:50:38:53:d9" and 1378079999<=pe.signatures[i].not_after)
}
