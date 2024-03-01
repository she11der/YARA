import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Df6Fa580F84493C414Ee0E431086737 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "27afa64e-0c9e-58ca-a4e1-db97cde66427"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15462-L15478"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ef244587c9eb1e1cb2f8a9c161e5dd9ff70e9764586f16e011334400ee400ed9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="7d:f6:fa:58:0f:84:49:3c:41:4e:e0:e4:31:08:67:37" and 1477440000<=pe.signatures[i].not_after)
}
