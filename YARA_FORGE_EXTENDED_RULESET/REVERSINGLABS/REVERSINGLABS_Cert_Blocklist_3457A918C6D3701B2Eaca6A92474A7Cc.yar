import "pe"

rule REVERSINGLABS_Cert_Blocklist_3457A918C6D3701B2Eaca6A92474A7Cc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "12526715-7b54-5c31-aa2a-b77ed067e3ee"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1636-L1652"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "70d4bece52a86bfe8958f6d4195b833cea609596e3b68bb90087c262501bd462"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KONSALTING PLUS OOO" and pe.signatures[i].serial=="34:57:a9:18:c6:d3:70:1b:2e:ac:a6:a9:24:74:a7:cc" and 1432252799<=pe.signatures[i].not_after)
}
