import "pe"

rule REVERSINGLABS_Cert_Blocklist_Afe8Fee94B41422E01E4897Bcd52D0A4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "83d08ca6-2a0b-5da3-8d53-7bf8bcc361cf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9592-L9610"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "02c55b182bc9843334baed9c0a7cca2c88cd1de00ca9b47b10ec79b7a5acf9bb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TLGM ApS" and (pe.signatures[i].serial=="00:af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4" or pe.signatures[i].serial=="af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4") and 1617062400<=pe.signatures[i].not_after)
}
