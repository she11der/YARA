import "pe"

rule REVERSINGLABS_Cert_Blocklist_133565779808C3B79D8E3F70A9C3Ffac : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bc3f54a6-723d-5de5-9a59-2be8a005cedc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6618-L6634"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b9fb2e3cc150b0278e67c673f7c01174c30b2cc4458c9c5e573661071795b793"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Istok" and pe.signatures[i].serial=="13:35:65:77:98:08:c3:b7:9d:8e:3f:70:a9:c3:ff:ac" and 1605019819<=pe.signatures[i].not_after)
}
