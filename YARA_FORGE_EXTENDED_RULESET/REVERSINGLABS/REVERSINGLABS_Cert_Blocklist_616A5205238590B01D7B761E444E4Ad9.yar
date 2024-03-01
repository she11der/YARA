import "pe"

rule REVERSINGLABS_Cert_Blocklist_616A5205238590B01D7B761E444E4Ad9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "09e9e481-c767-53d3-9af1-11dec636cafb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15882-L15898"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "463ccd3ace9021569a7a6d5fcbaadf34b15d2b07baf3df526b271b547cf2bbc5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lerges" and pe.signatures[i].serial=="61:6a:52:05:23:85:90:b0:1d:7b:76:1e:44:4e:4a:d9" and 1421452800<=pe.signatures[i].not_after)
}
