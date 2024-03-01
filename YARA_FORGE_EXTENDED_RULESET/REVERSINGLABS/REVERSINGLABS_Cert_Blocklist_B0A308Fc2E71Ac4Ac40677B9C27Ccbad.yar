import "pe"

rule REVERSINGLABS_Cert_Blocklist_B0A308Fc2E71Ac4Ac40677B9C27Ccbad : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7e13e257-a264-5a40-b670-889045504acf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7386-L7404"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "21fd7625399c939b6d03100b731709616d206a3811197af2b86991be9d89b4eb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Volpayk LLC" and (pe.signatures[i].serial=="00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad" or pe.signatures[i].serial=="b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad") and 1611705600<=pe.signatures[i].not_after)
}
