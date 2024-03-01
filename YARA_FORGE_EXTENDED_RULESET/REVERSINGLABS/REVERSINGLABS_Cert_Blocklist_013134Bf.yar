import "pe"

rule REVERSINGLABS_Cert_Blocklist_013134Bf : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "a3292707-c481-56a8-abf9-e1a762c76cb6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L819-L835"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1ade100c310c22bce25bcc6687855bd4eb6364b64cf31514b2548509a16e4a36"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Organisatie - G2" and pe.signatures[i].serial=="01:31:34:bf" and 1308182400<=pe.signatures[i].not_after)
}
