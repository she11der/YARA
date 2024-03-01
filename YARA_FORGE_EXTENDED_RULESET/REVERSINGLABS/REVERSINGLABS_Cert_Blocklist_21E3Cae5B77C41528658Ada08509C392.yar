import "pe"

rule REVERSINGLABS_Cert_Blocklist_21E3Cae5B77C41528658Ada08509C392 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fdb1903b-15c1-5cb7-892f-58957303d3b4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8416-L8432"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2e24ed0bd0bf3c36cae4bf106a2c17386bfb58b76372068be9745c2d501f30fc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Network Design International Holdings Limited" and pe.signatures[i].serial=="21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92" and 1609233559<=pe.signatures[i].not_after)
}
