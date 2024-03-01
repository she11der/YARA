import "pe"

rule REVERSINGLABS_Cert_Blocklist_70E1Ebd170Db8102D8C28E58392E5632 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e3b0f68c-8cc9-5275-988a-8d955ea25a47"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5158-L5174"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e1738eddc1da0876a373ee7f35bff155d56c1b98a23cb117c0e7a966f8fa3c92"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Equal Cash Technologies Limited" and pe.signatures[i].serial=="70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32" and 1599264000<=pe.signatures[i].not_after)
}
