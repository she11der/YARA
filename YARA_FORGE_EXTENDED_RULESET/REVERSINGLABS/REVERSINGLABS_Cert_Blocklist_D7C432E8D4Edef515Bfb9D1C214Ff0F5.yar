import "pe"

rule REVERSINGLABS_Cert_Blocklist_D7C432E8D4Edef515Bfb9D1C214Ff0F5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5aed508e-2da1-52a0-98f3-52e903e95b7d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5366-L5384"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "63741513f3ab2f51ecd66dc973239c9dc194b86504fe26b2dd4a7f31299e5497"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and (pe.signatures[i].serial=="00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5" or pe.signatures[i].serial=="d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5") and 1601596800<=pe.signatures[i].not_after)
}
