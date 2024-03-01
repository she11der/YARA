import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Fda1E121B61Adeca936A6Aebe079303 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fba98d6b-dc09-5294-ad86-2f4e0d8ad320"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2432-L2448"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "70a04c83e79c98024bacf1688bb46d80c9b8491e25dd32d6d92bf3cf61c62e48"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Laizhou wanlei stone Co., LTD" and pe.signatures[i].serial=="4f:da:1e:12:1b:61:ad:ec:a9:36:a6:ae:be:07:93:03" and 1310687999<=pe.signatures[i].not_after)
}
