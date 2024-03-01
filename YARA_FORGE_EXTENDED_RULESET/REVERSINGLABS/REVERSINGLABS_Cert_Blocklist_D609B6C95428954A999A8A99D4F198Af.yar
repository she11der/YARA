import "pe"

rule REVERSINGLABS_Cert_Blocklist_D609B6C95428954A999A8A99D4F198Af : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4ce9b2ce-5dda-5741-bd29-cadae44c3b28"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7540-L7558"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a124f80d599051ecd7c17e6818d181ea018db14c9f0514bbcc5b677ba3656d65"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fudl" and (pe.signatures[i].serial=="00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af" or pe.signatures[i].serial=="d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af") and 1612828800<=pe.signatures[i].not_after)
}
