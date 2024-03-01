import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F0Ed5318848703405D40F7C62D0F39A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "30e3a977-caa3-5ae0-9cd0-6b2ce62ccebd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7314-L7330"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "484932ddfe614fd5ab22361ab281cda62803c98279f938aa5237237fae6a95d6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and pe.signatures[i].serial=="0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a" and 1614729600<=pe.signatures[i].not_after)
}
