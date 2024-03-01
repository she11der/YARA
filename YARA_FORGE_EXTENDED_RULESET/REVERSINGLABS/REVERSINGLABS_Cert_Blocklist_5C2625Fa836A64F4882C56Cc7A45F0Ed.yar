import "pe"

rule REVERSINGLABS_Cert_Blocklist_5C2625Fa836A64F4882C56Cc7A45F0Ed : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "db968865-fb1e-57b5-8968-6510e83c02ac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15444-L15460"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "85e187684d62c33ef6f69323b837ef2d44facab8278b512d7bd6afd49eaed976"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="5c:26:25:fa:83:6a:64:f4:88:2c:56:cc:7a:45:f0:ed" and 1474416000<=pe.signatures[i].not_after)
}
