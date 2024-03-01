import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Bab6A2Aa84B495D9E554A4C42C0126D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7b6d364c-3e27-5314-b604-d44bb408fc4e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5884-L5900"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "79b6df421c78fd3e2f05a60f7d875e02519297a0278614c9f63dff8b1b2a2d18"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NOSOV SP Z O O" and pe.signatures[i].serial=="0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d" and 1597971600<=pe.signatures[i].not_after)
}
