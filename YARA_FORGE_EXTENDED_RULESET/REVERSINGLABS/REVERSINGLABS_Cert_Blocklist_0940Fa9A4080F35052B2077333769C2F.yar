import "pe"

rule REVERSINGLABS_Cert_Blocklist_0940Fa9A4080F35052B2077333769C2F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "358391b7-649b-5792-b4bd-d97b388c5d12"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7922-L7938"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "45636ea33751fea61572539fe6f28bccd05df9b6b9e7f2d77bb738f7c69c53a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROFF LAIN, OOO" and pe.signatures[i].serial=="09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f" and 1603497600<=pe.signatures[i].not_after)
}
