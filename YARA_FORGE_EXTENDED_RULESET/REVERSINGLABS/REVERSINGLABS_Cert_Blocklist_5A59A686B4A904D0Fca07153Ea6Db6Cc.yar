import "pe"

rule REVERSINGLABS_Cert_Blocklist_5A59A686B4A904D0Fca07153Ea6Db6Cc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "018e511f-191d-5fd4-8ab0-0e5bbff44d58"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3306-L3322"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7597b2ba870ec58ac0786a97fb92956406fe019c81f6176cc1a581988d3a9632"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABADAN PIZZA LTD" and pe.signatures[i].serial=="5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc" and 1563403380<=pe.signatures[i].not_after)
}
