import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E0Ccbdfb4777E10Ea6221B90Dc350C2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "64007bd7-b273-5579-8224-68337f1bc54d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5974-L5990"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "08a1ff7cc3a7680fdbb3235a7b46709cd4ba530a9afeab4344671db9fe893cc4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and pe.signatures[i].serial=="6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2" and 1603046620<=pe.signatures[i].not_after)
}
