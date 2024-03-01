import "pe"

rule REVERSINGLABS_Cert_Blocklist_307642E1F3A92C6Cc2E7Fb6E18F2Ddcb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6dd35efb-daea-5668-a01d-f5b80371b04c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15666-L15682"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8c96fbd10672b0b258a80f3abaf0320540c5ff0a4636f011cfe7cfa8ccc482d0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IBM" and pe.signatures[i].serial=="30:76:42:e1:f3:a9:2c:6c:c2:e7:fb:6e:18:f2:dd:cb" and 1500422400<=pe.signatures[i].not_after)
}
