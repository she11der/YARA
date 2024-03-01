import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Fb6Bae8834Edd8D3D58818Edc86D7D7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "52b11933-f22c-53ea-88b7-75b3242907dd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5674-L5690"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a8cec0479bfd53f34e291d56538187c05375e80d20af7f0af08f0db8e1d6ed22"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tramplink LLC" and pe.signatures[i].serial=="5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7" and 1600781989<=pe.signatures[i].not_after)
}
