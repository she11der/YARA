import "pe"

rule REVERSINGLABS_Cert_Blocklist_76D8D908Eed2F9857Dc5676A680Ceac9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7eae73e-6b12-5507-846e-d3b409243adf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15756-L15772"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "87f9930967d5832d3003672eeb89669b54feed1ca2ea5eec478c50e3cb7a7571"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="76:d8:d9:08:ee:d2:f9:85:7d:c5:67:6a:68:0c:ea:c9" and 1467158400<=pe.signatures[i].not_after)
}
