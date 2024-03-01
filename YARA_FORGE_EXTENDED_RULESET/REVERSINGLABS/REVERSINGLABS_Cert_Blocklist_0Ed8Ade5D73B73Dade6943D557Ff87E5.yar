import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ed8Ade5D73B73Dade6943D557Ff87E5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dbfae40c-2f81-5daf-8655-d06ae38ffa8f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5920-L5936"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7796b6e7da900be8634e7f1e51cda1275ab1e7c2709af7ecaa8777ab0b518494"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rumikon LLC" and pe.signatures[i].serial=="0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5" and 1597885200<=pe.signatures[i].not_after)
}
