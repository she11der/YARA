import "pe"

rule REVERSINGLABS_Cert_Blocklist_54Cd7Ae1C27F1421136Ed25088F4979A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "76999ae0-966e-5c52-8e00-a3af8afd8fae"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7124-L7140"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c7cd84a225216ff1464a147c2572de2b0a2f69f7a315cdebef5ad2bab843b72a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and pe.signatures[i].serial=="54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a" and 1616371200<=pe.signatures[i].not_after)
}
