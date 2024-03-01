import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Ad60Cea73E1Dd1A3E6C02D9B339C380 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "80b39632-29a7-5932-a47b-736a9e8ed686"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3342-L3358"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fb83cf25be19e7cccd2c8369c3a37a90af72cb2f76db3619b8311d2a851335a8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CUS Software GmbH" and pe.signatures[i].serial=="3a:d6:0c:ea:73:e1:dd:1a:3e:6c:02:d9:b3:39:c3:80" and 1567036800<=pe.signatures[i].not_after)
}
