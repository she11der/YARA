import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bebef5C533Ce92Efc402Fab8605C43Ec : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "59d3dd01-47bc-59ee-8fe7-fd5b1af8f9f4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4270-L4288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "daa57ad622799467c60693060e6c9eea18bdf0bb26f178e8b03453aab486ccf4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO VEKTOR" and (pe.signatures[i].serial=="00:be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec" or pe.signatures[i].serial=="be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec") and 1587513600<=pe.signatures[i].not_after)
}
