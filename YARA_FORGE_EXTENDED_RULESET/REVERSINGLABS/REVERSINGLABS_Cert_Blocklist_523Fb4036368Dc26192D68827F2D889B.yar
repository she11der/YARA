import "pe"

rule REVERSINGLABS_Cert_Blocklist_523Fb4036368Dc26192D68827F2D889B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bfce2ea9-cbe0-5b58-b7f8-39d2dad28db6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3884-L3900"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1886a046305637d335c493972560de56d8186bf99183aed5e2040b2e530fc22"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO MEDUZA SERVICE GROUP" and pe.signatures[i].serial=="52:3f:b4:03:63:68:dc:26:19:2d:68:82:7f:2d:88:9b" and 1586847880<=pe.signatures[i].not_after)
}
