import "pe"

rule REVERSINGLABS_Cert_Blocklist_36Be4Ad457F062Fa77D87595B8Ccc8Cf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Careto malware."
		author = "ReversingLabs"
		id = "224ec8ed-e4f0-5d1b-8cdd-a669a7e3e859"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L153-L169"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d19a6f22a1e702a4da69c867195722adf8f1dd84539f2c584af428fe4b1caf79"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TecSystem Ltd." and pe.signatures[i].serial=="36:be:4a:d4:57:f0:62:fa:77:d8:75:95:b8:cc:c8:cf" and 1372377599<=pe.signatures[i].not_after)
}
