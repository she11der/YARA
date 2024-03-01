import "pe"

rule REVERSINGLABS_Cert_Blocklist_02B6656292310B84022Db5541Bc48Faf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d679238f-a697-5322-815c-9986c9d24032"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11236-L11252"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "40b570b28e10ebd2a1ba515dc3fa45bdb5c0b76044e4dda7a6819976072a67a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DILA d.o.o." and pe.signatures[i].serial=="02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af" and 1613865600<=pe.signatures[i].not_after)
}
