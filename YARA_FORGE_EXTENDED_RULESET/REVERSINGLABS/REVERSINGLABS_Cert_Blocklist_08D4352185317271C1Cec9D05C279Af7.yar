import "pe"

rule REVERSINGLABS_Cert_Blocklist_08D4352185317271C1Cec9D05C279Af7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0165920f-5f4d-5b35-990d-120786b4c5ba"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5598-L5614"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b240962ab23729b241413ed1e53ac6541bf6b8a673c57522efd0cfe0c7eb9dd4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Retalit LLC" and pe.signatures[i].serial=="08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7" and 1596585601<=pe.signatures[i].not_after)
}
