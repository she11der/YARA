import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Ae5B177Ac3A7Ce2Aadf1C891B574924 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c72b8b2a-3e49-5ac3-ab4d-55b86ce7f061"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7786-L7804"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "03ac299459a1aaf2e4a2e62884cd321e16100fee78b4b0e271acdd8a4e32525c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Kolorit" and (pe.signatures[i].serial=="00:9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24" or pe.signatures[i].serial=="9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24") and 1608076800<=pe.signatures[i].not_after)
}
