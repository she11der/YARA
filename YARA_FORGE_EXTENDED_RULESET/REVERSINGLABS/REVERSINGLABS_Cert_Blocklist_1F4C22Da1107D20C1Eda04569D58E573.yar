import "pe"

rule REVERSINGLABS_Cert_Blocklist_1F4C22Da1107D20C1Eda04569D58E573 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4ff75d18-926e-51aa-8e1c-b9699669bbd0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L477-L493"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fe19c4b21c3b70ec571461ca6d9c370a971c01f2d68e3c3916aa1fa0f13b20f8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PlanView, Inc." and pe.signatures[i].serial=="1f:4c:22:da:11:07:d2:0c:1e:da:04:56:9d:58:e5:73" and 1366156799<=pe.signatures[i].not_after)
}
