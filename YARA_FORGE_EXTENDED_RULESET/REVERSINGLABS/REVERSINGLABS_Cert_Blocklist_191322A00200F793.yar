import "pe"

rule REVERSINGLABS_Cert_Blocklist_191322A00200F793 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4011e54c-ca28-536f-8759-077fcce6d45f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1942-L1958"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1b816785f86189817c124636e50a0f369ec85cfd898223c4ba43758a877f1cf3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PRABHAKAR NARAYAN" and pe.signatures[i].serial=="19:13:22:a0:02:00:f7:93" and 1442966399<=pe.signatures[i].not_after)
}
