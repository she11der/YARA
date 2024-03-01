import "pe"

rule REVERSINGLABS_Cert_Blocklist_719C17A823839Dca813Ee85888B3B39A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ca5b9ec0-2c46-50db-bc47-b3c6c61e990e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16008-L16024"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a160ada48048e11632082e7538459554d77d31539e53709cd897f3c454af8236"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="71:9c:17:a8:23:83:9d:ca:81:3e:e8:58:88:b3:b3:9a" and 1479686400<=pe.signatures[i].not_after)
}
