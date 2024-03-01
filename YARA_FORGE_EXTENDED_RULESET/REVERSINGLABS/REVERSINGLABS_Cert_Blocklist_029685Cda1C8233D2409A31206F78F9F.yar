import "pe"

rule REVERSINGLABS_Cert_Blocklist_029685Cda1C8233D2409A31206F78F9F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7894a48-459b-574f-9df3-8505578de42b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7522-L7538"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d541ce73e5039541ea221f27cc4d033f0c477e41a148206c26cc39ae07c4caaa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOTO TRADE, dru\\xC5\\xBEba za posredovanje, d.o.o." and pe.signatures[i].serial=="02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f" and 1612396800<=pe.signatures[i].not_after)
}
