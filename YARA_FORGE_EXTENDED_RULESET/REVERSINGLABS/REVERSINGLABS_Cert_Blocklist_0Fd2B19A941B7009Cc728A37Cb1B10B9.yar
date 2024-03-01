import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fd2B19A941B7009Cc728A37Cb1B10B9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "125c0b95-82bb-5900-8e8c-4359b8cd18ab"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14168-L14184"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6b5cc47f4df9e57c59bc66c32188e02390d4855a1b9e56bd7471fd641a245c3c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAR AND CILLA LTD" and pe.signatures[i].serial=="0f:d2:b1:9a:94:1b:70:09:cc:72:8a:37:cb:1b:10:b9" and 1560470400<=pe.signatures[i].not_after)
}
