import "pe"

rule REVERSINGLABS_Cert_Blocklist_0E808F231515Bc519Eea1A73Cdf3266F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Careto malware."
		author = "ReversingLabs"
		id = "1f1eb5c2-bfef-58df-b51e-c558d87cd5d2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L135-L151"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "05e466e304ed7a8f5c1c93aac4a4b7019d6fb1e07aeb45d078b657f838d1f3bd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TecSystem Ltd." and pe.signatures[i].serial=="0e:80:8f:23:15:15:bc:51:9e:ea:1a:73:cd:f3:26:6f" and 1468799999<=pe.signatures[i].not_after)
}
