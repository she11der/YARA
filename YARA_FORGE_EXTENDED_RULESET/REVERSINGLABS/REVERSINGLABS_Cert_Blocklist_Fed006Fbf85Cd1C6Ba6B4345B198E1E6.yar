import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fed006Fbf85Cd1C6Ba6B4345B198E1E6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ab84282d-9c35-5e52-a117-1d85c03cc6f4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7464-L7482"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0360c6760f1018f9388ef5639ab2306879134f33da12677f954fa31b8a71aa16"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LoL d.o.o." and (pe.signatures[i].serial=="00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6" or pe.signatures[i].serial=="fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6") and 1614297600<=pe.signatures[i].not_after)
}
