import "pe"

rule REVERSINGLABS_Cert_Blocklist_83320D93Dd8Cf16D11F99B1078B0A7Cb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "12ce9be9-4644-5b59-aed2-ce4b04fcc46a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13966-L13984"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "94ec5e05357767cc0c4cd1fc8ff6d1a366359ba699c43f3710204d761e7e707f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRANS LTD" and (pe.signatures[i].serial=="00:83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb" or pe.signatures[i].serial=="83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb") and 1524614400<=pe.signatures[i].not_after)
}
