import "pe"

rule REVERSINGLABS_Cert_Blocklist_2F96A89Bfec6E44Dd224E8Fd7E72D9Bb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bdca8435-c1fd-598d-bd82-20a3a3b2a959"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11272-L11288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c0c8e5c0e2e120ee6b055e9a6b2af3d424bed0832c2619beab658fe01757f69f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and pe.signatures[i].serial=="2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb" and 1625529600<=pe.signatures[i].not_after)
}
