import "pe"

rule REVERSINGLABS_Cert_Blocklist_48Cad4E6966E22D6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing OSX DokSpy backdoor."
		author = "ReversingLabs"
		id = "22d62d7e-3f76-5f6b-a3f1-a6b087fb63e2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2176-L2192"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7733b8a97d9f3538db04309a2e3f9df6cb64930b0b6f7f241c3e629be2dd7804"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Developer ID Application: Seven Muller (FUP9692NN6)" and pe.signatures[i].serial=="48:ca:d4:e6:96:6e:22:d6" and 1492732799<=pe.signatures[i].not_after)
}
