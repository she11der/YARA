import "pe"

rule REVERSINGLABS_Cert_Blocklist_E161F76Da3B5E4623892C8E6Fda1Ea3D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "386c81ef-87aa-514e-81d7-dddfb90e0dc2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7766-L7784"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "883545593b48aa11c11f7fa1a1f77c62321ea86067f1ed108dcd00c8c6cd3495"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TGN Nedelica d.o.o." and (pe.signatures[i].serial=="00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d" or pe.signatures[i].serial=="e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d") and 1604966400<=pe.signatures[i].not_after)
}
