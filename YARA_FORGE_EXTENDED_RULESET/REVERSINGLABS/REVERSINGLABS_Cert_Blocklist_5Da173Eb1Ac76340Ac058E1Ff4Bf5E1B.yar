import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Da173Eb1Ac76340Ac058E1Ff4Bf5E1B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0f9fa6c6-372d-5948-94ba-9e3fee956647"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16456-L16472"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "71da69fca275caead6a822e6587e0a07fc882f712afeafe18f4a595c269f6737"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALISA LTD" and pe.signatures[i].serial=="5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b" and 1550793600<=pe.signatures[i].not_after)
}
