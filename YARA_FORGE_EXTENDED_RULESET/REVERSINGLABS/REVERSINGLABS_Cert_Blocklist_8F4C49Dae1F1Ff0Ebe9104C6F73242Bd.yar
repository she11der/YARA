import "pe"

rule REVERSINGLABS_Cert_Blocklist_8F4C49Dae1F1Ff0Ebe9104C6F73242Bd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b7731056-1674-5375-a3cb-69632670d6d9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9648-L9666"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a8c99cc30b791a76fe3cd48184bf95ee47abb30bd200128efd2f5295ee18f7b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Contact Merger Holding ApS" and (pe.signatures[i].serial=="00:8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd" or pe.signatures[i].serial=="8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd") and 1636039748<=pe.signatures[i].not_after)
}
