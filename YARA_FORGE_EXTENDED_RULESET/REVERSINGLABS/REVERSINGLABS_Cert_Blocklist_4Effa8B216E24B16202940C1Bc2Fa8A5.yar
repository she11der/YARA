import "pe"

rule REVERSINGLABS_Cert_Blocklist_4Effa8B216E24B16202940C1Bc2Fa8A5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "541a169e-a263-5901-9d8e-768306b8b8ba"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L189-L205"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b5282fc85bbbee50c5307fff923e9e477fed8c011288e2ebd61c4b3ee801bc62"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Henan Maijiamai Technology Co., Ltd." and pe.signatures[i].serial=="4e:ff:a8:b2:16:e2:4b:16:20:29:40:c1:bc:2f:a8:a5" and 1404691199<=pe.signatures[i].not_after)
}
