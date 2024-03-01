import "pe"

rule REVERSINGLABS_Cert_Blocklist_8B3333D32B2C2A1D33B41Ba5Db9D4D2D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7f72cd2-0bf4-5aa7-804e-4ae354eda055"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8942-L8960"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cdb3f1983ed17df22d17c6321bc2ead2c391d70fdca4a9f6f4784f62196b85d0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89, s.r.o." and (pe.signatures[i].serial=="00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or pe.signatures[i].serial=="8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d") and 1620000000<=pe.signatures[i].not_after)
}
