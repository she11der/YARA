import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cbf91988Fb83511De1B3A7A520712E9C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2d71058-f7b9-594f-b099-75aa4774306f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3636-L3654"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5862a8ec43d2e545f36b815ada2bb31c4384a8161c6956a31f3bd517532923fd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (pe.signatures[i].serial=="00:cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c" or pe.signatures[i].serial=="cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c") and 1578786662<=pe.signatures[i].not_after)
}
