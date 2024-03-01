import "pe"

rule REVERSINGLABS_Cert_Blocklist_6B6Daef5Be29F20Ddce4B0F5E9Fa6Ea5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "55611c9a-d45d-55fa-8e5e-a5621223cc9d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2524-L2540"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "edd2f302d2fac65f6a93372a24c3f80757f2b175af661032917366e9629c5491"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Calibration Consultants" and pe.signatures[i].serial=="6b:6d:ae:f5:be:29:f2:0d:dc:e4:b0:f5:e9:fa:6e:a5" and 1280447999<=pe.signatures[i].not_after)
}
