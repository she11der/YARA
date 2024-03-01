import "pe"

rule REVERSINGLABS_Cert_Blocklist_57C3717C5E2Ce9A2E0Cf0340C03F458E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "47207784-5aee-5fa3-bed9-2c12d9932c38"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17236-L17252"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fd710146874528c43ad8a9f847b7704c44ba4564cf79e20e6b23aa98b0ee2ea5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Citizen Travel Ltd" and pe.signatures[i].serial=="57:c3:71:7c:5e:2c:e9:a2:e0:cf:03:40:c0:3f:45:8e" and 1450915200<=pe.signatures[i].not_after)
}
