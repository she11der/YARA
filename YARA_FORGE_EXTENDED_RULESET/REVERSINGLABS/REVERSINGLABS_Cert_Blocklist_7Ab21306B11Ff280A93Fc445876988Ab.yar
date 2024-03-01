import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Ab21306B11Ff280A93Fc445876988Ab : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "656bb2a6-bb41-5190-af10-280351e64c66"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8584-L8600"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0cda954aa807336a6737716d0fa43d696376c240ab7be9d8477baf8800604bf1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABC BIOS d.o.o." and pe.signatures[i].serial=="7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab" and 1611014400<=pe.signatures[i].not_after)
}
