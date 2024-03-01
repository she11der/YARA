import "pe"

rule REVERSINGLABS_Cert_Blocklist_B3F906E5E6B2Cf61C5E51Be79B4E8777 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dc826355-bd15-58b3-adcb-55b704f03c0d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4460-L4478"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "037e154854c1128fb73d2221c2b7d7211d977492378614fcf4fde959207e34b3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Accelerate Technologies Ltd" and (pe.signatures[i].serial=="00:b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77" or pe.signatures[i].serial=="b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77") and 1594900020<=pe.signatures[i].not_after)
}
