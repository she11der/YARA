import "pe"

rule REVERSINGLABS_Cert_Blocklist_047801D5B55C800B48411Fd8C320Ca5B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "602b8c18-3dad-55b9-bb47-3f9835a049ac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7296-L7312"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ef26b4e3c658f53f3048d10bd1b7a2a198cd402e1b7c60e84adadb4f236ccb5d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and pe.signatures[i].serial=="04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b" and 1614297600<=pe.signatures[i].not_after)
}
