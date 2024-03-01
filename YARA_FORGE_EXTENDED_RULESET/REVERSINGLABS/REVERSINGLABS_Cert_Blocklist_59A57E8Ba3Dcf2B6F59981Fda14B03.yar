import "pe"

rule REVERSINGLABS_Cert_Blocklist_59A57E8Ba3Dcf2B6F59981Fda14B03 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "12c80895-57fd-5341-b3ef-d59c25d4c234"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6994-L7010"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6e77c7d0bd7e5e9bc8880cc6ffc3f5f4f738e3dde22c270ad7a6f6672a99de53"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Medium LLC" and pe.signatures[i].serial=="59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03" and 1609113600<=pe.signatures[i].not_after)
}
