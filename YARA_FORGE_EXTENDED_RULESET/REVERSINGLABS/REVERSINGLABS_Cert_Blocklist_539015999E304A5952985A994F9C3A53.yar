import "pe"

rule REVERSINGLABS_Cert_Blocklist_539015999E304A5952985A994F9C3A53 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ccb4da10-3178-5d8f-be17-9c689e794418"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6236-L6252"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "feeb1710bd5b048c689a2e45575529624cd1622dcc73db8fe7de6c133fdc5698"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Service lab LLC" and pe.signatures[i].serial=="53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53" and 1599181200<=pe.signatures[i].not_after)
}
