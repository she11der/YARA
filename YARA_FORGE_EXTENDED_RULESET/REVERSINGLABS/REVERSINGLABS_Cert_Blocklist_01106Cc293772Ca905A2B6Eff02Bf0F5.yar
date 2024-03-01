import "pe"

rule REVERSINGLABS_Cert_Blocklist_01106Cc293772Ca905A2B6Eff02Bf0F5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1ec81090-91a1-5019-be91-14f60d6722fc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9186-L9202"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "81e19c06de4546a2cee974230ef7aa15291f20f2e6b6f89c9b12107c26836b5e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DMR Consulting Ltd." and pe.signatures[i].serial=="01:10:6c:c2:93:77:2c:a9:05:a2:b6:ef:f0:2b:f0:f5" and 1627084800<=pe.signatures[i].not_after)
}
