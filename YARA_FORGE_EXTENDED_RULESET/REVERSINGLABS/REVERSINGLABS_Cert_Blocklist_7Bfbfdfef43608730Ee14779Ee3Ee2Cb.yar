import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Bfbfdfef43608730Ee14779Ee3Ee2Cb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fdc2f6a0-8fae-537e-812f-b0c292f76b1e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4124-L4140"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f8f233b78e9d3558b0cd7978e3c5fa32645a3bb706c6fdec7f1e4195cf513f10"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CSTech Software Inc." and pe.signatures[i].serial=="7b:fb:fd:fe:f4:36:08:73:0e:e1:47:79:ee:3e:e2:cb" and 1590537600<=pe.signatures[i].not_after)
}
