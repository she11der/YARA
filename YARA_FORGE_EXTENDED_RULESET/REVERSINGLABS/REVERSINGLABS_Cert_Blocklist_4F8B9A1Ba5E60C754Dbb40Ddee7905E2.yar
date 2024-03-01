import "pe"

rule REVERSINGLABS_Cert_Blocklist_4F8B9A1Ba5E60C754Dbb40Ddee7905E2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9b6ba6bb-a796-59e1-a38b-04d4b60a99a6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L621-L637"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a0d07d47cd41db5dc170a29607b6c1f2e3b7c0785f83b211f68f9cb9368e350"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NOX Entertainment Co., Ltd" and pe.signatures[i].serial=="4f:8b:9a:1b:a5:e6:0c:75:4d:bb:40:dd:ee:79:05:e2" and 1348617599<=pe.signatures[i].not_after)
}
