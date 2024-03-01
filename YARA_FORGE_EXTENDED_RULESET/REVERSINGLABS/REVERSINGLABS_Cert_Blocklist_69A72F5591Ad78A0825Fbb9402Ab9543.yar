import "pe"

rule REVERSINGLABS_Cert_Blocklist_69A72F5591Ad78A0825Fbb9402Ab9543 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "938cdd31-433d-5df7-b00e-54a7e440810b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10390-L10406"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "72ca07b7722f9506c5c42b5e58c5ce9b3a7d607164a5f265015769f2831cd588"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PUSH BANK LIMITED" and pe.signatures[i].serial=="69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43" and 1581811200<=pe.signatures[i].not_after)
}
