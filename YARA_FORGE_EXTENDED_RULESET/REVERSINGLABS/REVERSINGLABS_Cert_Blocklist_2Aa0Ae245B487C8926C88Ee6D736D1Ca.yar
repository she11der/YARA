import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Aa0Ae245B487C8926C88Ee6D736D1Ca : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2d61fd7-2392-5d75-9c5b-4e4fddfc7a83"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8282-L8298"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5a362175600552983ae838ca18aa378dc748b8b68bd8b67a9387794d983ed1a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PILOTE SPRL" and pe.signatures[i].serial=="2a:a0:ae:24:5b:48:7c:89:26:c8:8e:e6:d7:36:d1:ca" and 1612262280<=pe.signatures[i].not_after)
}
