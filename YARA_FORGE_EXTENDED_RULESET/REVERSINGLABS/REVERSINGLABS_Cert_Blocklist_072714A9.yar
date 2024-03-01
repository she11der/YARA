import "pe"

rule REVERSINGLABS_Cert_Blocklist_072714A9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "15ad6936-78a4-58b1-8c68-27ec4ed38649"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L981-L997"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8bea4cfb60056446043ef90a7d01ecc52d82d9e7005a145a4daa61a522ecd2ae"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digisign Server ID (Enrich)" and pe.signatures[i].serial=="07:27:14:a9" and 1320191999<=pe.signatures[i].not_after)
}
