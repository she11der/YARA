import "pe"

rule REVERSINGLABS_Cert_Blocklist_E69A6De0074Ece38C2F30F0D4A808456 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "17571f1e-1dce-5216-8f45-467e5d77ccf1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8376-L8394"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "21d8641d2394120847044f0e6f4d868095a1e30c0b594a3d045877ab9b3808a1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Semantic" and (pe.signatures[i].serial=="00:e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56" or pe.signatures[i].serial=="e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56") and 1611532800<=pe.signatures[i].not_after)
}
