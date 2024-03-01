import "pe"

rule REVERSINGLABS_Cert_Blocklist_A03Ea3A4Fa772B17037A0B80F1F968Aa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cbc0c6ca-fab2-531e-b368-4d3fdc72509f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7806-L7824"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e2044c6ddb80f3add13dfc3b623d0460ce8e9a66c5a98582f80d906edbbbd829"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREVOKAPITAL, s.r.o." and (pe.signatures[i].serial=="00:a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa" or pe.signatures[i].serial=="a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa") and 1608076800<=pe.signatures[i].not_after)
}
