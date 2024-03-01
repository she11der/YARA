import "pe"

rule REVERSINGLABS_Cert_Blocklist_C8442A8185082Ef1Ed7Dc3Fff2176Aa7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2a56ff80-584b-5b8b-80ae-e763339cd17a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10088-L10106"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "74b1b48f0179187ea7bb8ef4663bf13da47f5c6405ecc5589706184564c05727"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ambidekstr LLC" and (pe.signatures[i].serial=="00:c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7" or pe.signatures[i].serial=="c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7") and 1616976000<=pe.signatures[i].not_after)
}
