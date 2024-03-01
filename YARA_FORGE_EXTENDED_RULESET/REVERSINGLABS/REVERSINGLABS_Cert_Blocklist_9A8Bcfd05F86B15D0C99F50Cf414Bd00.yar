import "pe"

rule REVERSINGLABS_Cert_Blocklist_9A8Bcfd05F86B15D0C99F50Cf414Bd00 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4446aead-9505-545a-8d3a-6ad844d348d3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6578-L6596"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "803d70dddeff51b753b577ea196b12570847c6875ae676a2d12cf1ca9323be34"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AI Software a.s." and (pe.signatures[i].serial=="00:9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00" or pe.signatures[i].serial=="9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00") and 1592442000<=pe.signatures[i].not_after)
}
