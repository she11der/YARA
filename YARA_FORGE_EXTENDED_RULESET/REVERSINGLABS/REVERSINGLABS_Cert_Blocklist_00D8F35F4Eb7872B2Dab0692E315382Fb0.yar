import "pe"

rule REVERSINGLABS_Cert_Blocklist_00D8F35F4Eb7872B2Dab0692E315382Fb0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2c051732-76d7-5562-a79e-c5bbdc8373b2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L999-L1017"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "463757c59c32859163ea80e694e1f39239c857124aad3895f22f83b47645910c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "global trustee" and (pe.signatures[i].serial=="00:d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0" or pe.signatures[i].serial=="d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0") and 1300060800<=pe.signatures[i].not_after)
}
