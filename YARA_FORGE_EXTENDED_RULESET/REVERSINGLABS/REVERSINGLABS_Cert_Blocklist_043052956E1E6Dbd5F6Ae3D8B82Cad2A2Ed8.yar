import "pe"

rule REVERSINGLABS_Cert_Blocklist_043052956E1E6Dbd5F6Ae3D8B82Cad2A2Ed8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ac09f8ac-fbdd-5989-a7e7-07373a69213b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10990-L11006"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c29fb109c741437a3739f1c42aadace8f612ef1e3ea90e3e2bdd8a92c85e766a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ok.com" and pe.signatures[i].serial=="04:30:52:95:6e:1e:6d:bd:5f:6a:e3:d8:b8:2c:ad:2a:2e:d8" and 1662149613<=pe.signatures[i].not_after)
}
