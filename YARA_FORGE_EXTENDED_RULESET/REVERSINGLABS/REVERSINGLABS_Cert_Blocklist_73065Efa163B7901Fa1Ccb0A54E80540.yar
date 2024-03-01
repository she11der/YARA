import "pe"

rule REVERSINGLABS_Cert_Blocklist_73065Efa163B7901Fa1Ccb0A54E80540 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "949f55a9-7aa0-50de-bb81-fed5d27c3d24"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3270-L3286"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e420c37c04aa676c266a4c2c228063239815c173a83c39d426c5a674648f1934"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SOVA CONSULTANCY LTD" and pe.signatures[i].serial=="73:06:5e:fa:16:3b:79:01:fa:1c:cb:0a:54:e8:05:40" and 1548115200<=pe.signatures[i].not_after)
}
