import "pe"

rule REVERSINGLABS_Cert_Blocklist_B8F726508Cf1D7B7913Bf4Bbd1E5C19C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eb441b57-0f28-5609-b987-157e1f026b0c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11804-L11822"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ec05c7e41e309aff00ae819c63f5bdc8e4172c611779da345efd211e48c9efb1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Merkuri LLC" and (pe.signatures[i].serial=="00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or pe.signatures[i].serial=="b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c") and 1619568000<=pe.signatures[i].not_after)
}
