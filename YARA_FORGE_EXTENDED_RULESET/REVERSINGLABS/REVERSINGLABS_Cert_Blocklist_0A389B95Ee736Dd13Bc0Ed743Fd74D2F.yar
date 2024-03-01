import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A389B95Ee736Dd13Bc0Ed743Fd74D2F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "43cce248-2322-5607-8706-aeab046a30b9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L639-L655"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8b83e4aa47cea7cadf4b4a9f4e044478a62f4233e082fb52f9ed906d80a552aa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BUSTER ASSISTENCIA TECNICA ELETRONICA LTDA - ME" and pe.signatures[i].serial=="0a:38:9b:95:ee:73:6d:d1:3b:c0:ed:74:3f:d7:4d:2f" and 1351814399<=pe.signatures[i].not_after)
}
