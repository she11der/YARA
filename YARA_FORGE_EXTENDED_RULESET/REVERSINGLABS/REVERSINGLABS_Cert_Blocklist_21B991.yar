import "pe"

rule REVERSINGLABS_Cert_Blocklist_21B991 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "333a0901-21e7-5b4a-8daa-6a04fc2c4e86"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15242-L15258"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "54ca9b19adfc9357a3fb74f0670ad929319c4d06a7de7ae400f8285a31052276"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Web Nexus d.o.o." and pe.signatures[i].serial=="21:b9:91" and 1125477041<=pe.signatures[i].not_after)
}
