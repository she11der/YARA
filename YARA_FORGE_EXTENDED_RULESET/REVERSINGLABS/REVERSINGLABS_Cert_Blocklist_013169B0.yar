import "pe"

rule REVERSINGLABS_Cert_Blocklist_013169B0 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "a5f68c0a-635a-5aa9-94d2-7628999f06c2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L855-L871"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "354421ebad7fd0b73c9ba63630c91d481901ca9ec39be3c6b66843221e4b5aad"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid en Bedrijven" and pe.signatures[i].serial=="01:31:69:b0" and 1308182400<=pe.signatures[i].not_after)
}
