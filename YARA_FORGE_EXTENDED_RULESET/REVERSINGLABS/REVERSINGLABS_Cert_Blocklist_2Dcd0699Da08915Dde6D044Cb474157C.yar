import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Dcd0699Da08915Dde6D044Cb474157C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e1f56719-e726-5f81-99d4-937e343cbcc9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6068-L6084"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e1a3f27b8b9b642fe1ca73ec54d225f4470b53d0d06f2eea55ad1ad43ec67b39"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VENTE DE TOUT" and pe.signatures[i].serial=="2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c" and 1601830010<=pe.signatures[i].not_after)
}
