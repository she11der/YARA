import "pe"

rule REVERSINGLABS_Cert_Blocklist_Addbec454B5479Cabd940A72Df4500Af : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f2488d44-5a9a-5ab6-be6f-f3444f72444a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8206-L8224"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "799629791646c524d170b900339b87474aed73b7156a8c4dd20f7c13cbe97929"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHAT LIMITED" and (pe.signatures[i].serial=="00:ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af" or pe.signatures[i].serial=="ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af") and 1612828800<=pe.signatures[i].not_after)
}
