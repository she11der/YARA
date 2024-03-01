import "pe"

rule REVERSINGLABS_Cert_Blocklist_7E0Ccda0Ef37Acef6C2Ebe4538627E5C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4668ceb3-8bf2-5be4-9a1a-d0d902c35cf0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6636-L6654"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f13f9b70a2a3187522e4fff45a8a425863ad6242f82592aa9319c8d5fddeeefa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orangetree B.V." and (pe.signatures[i].serial=="00:7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c" or pe.signatures[i].serial=="7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c") and 1606159604<=pe.signatures[i].not_after)
}
