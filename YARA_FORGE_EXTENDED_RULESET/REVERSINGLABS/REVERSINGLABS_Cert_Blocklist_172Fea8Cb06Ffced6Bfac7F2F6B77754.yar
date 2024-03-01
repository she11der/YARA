import "pe"

rule REVERSINGLABS_Cert_Blocklist_172Fea8Cb06Ffced6Bfac7F2F6B77754 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0890bf55-ebd5-5b68-8047-14692a5f1ae7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17052-L17068"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8e1e3e7d002ce084600c5444dc9b0bad8771370cb7919a3bb5ebc899040e4cf2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="17:2f:ea:8c:b0:6f:fc:ed:6b:fa:c7:f2:f6:b7:77:54" and 1467936000<=pe.signatures[i].not_after)
}
