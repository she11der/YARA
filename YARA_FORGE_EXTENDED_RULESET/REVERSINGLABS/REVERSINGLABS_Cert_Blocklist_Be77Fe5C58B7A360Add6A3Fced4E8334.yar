import "pe"

rule REVERSINGLABS_Cert_Blocklist_Be77Fe5C58B7A360Add6A3Fced4E8334 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1bbaebe9-b3ca-5ee2-91ac-b2343ca8bb86"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6140-L6158"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cea0d217206562c0045843405802d3b2fad01bdb2a4cfb52057625b43f5f8eee"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Incar LLC" and (pe.signatures[i].serial=="00:be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34" or pe.signatures[i].serial=="be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34") and 1602530730<=pe.signatures[i].not_after)
}
