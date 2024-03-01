import "pe"

rule REVERSINGLABS_Cert_Blocklist_08653Ef2Ed9E6Ebb56Ffa7E93F963235 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9ac976c0-260f-5207-ae39-bbb722c38a92"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3828-L3844"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5ae8d2fb03cd0f945c2f5eb86de4e5da4fbb1cdf233d8a808157304538ced872"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Haw Farm LIMITED" and pe.signatures[i].serial=="08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35" and 1581465601<=pe.signatures[i].not_after)
}
