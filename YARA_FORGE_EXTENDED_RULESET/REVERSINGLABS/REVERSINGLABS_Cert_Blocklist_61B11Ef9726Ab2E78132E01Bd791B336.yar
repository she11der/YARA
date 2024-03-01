import "pe"

rule REVERSINGLABS_Cert_Blocklist_61B11Ef9726Ab2E78132E01Bd791B336 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "573a024e-11f0-5cf9-8f0d-a946cdca34c5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7406-L7422"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1a8e72f31039a5a5602d0314f017a2596a23e4a796dc66167dfefc0c9790e3e3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Skalari" and pe.signatures[i].serial=="61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36" and 1609372800<=pe.signatures[i].not_after)
}
