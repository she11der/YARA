import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Efcf7Adc21F070E590D49Ddb8081397 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "df467418-9d57-5ad0-b396-2ef519a22989"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13112-L13128"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d60a5bbd50484d620ab60cfd40840abc541c2b7bc1005a9076b69ddd1b938652"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ding Ruan" and pe.signatures[i].serial=="4e:fc:f7:ad:c2:1f:07:0e:59:0d:49:dd:b8:08:13:97" and 1476921600<=pe.signatures[i].not_after)
}
