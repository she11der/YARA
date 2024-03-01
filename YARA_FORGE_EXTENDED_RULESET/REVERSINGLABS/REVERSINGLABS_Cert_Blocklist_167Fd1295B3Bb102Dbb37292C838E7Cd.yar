import "pe"

rule REVERSINGLABS_Cert_Blocklist_167Fd1295B3Bb102Dbb37292C838E7Cd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "42cf5f07-4c43-567c-a517-42c898658ab8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13782-L13798"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1cc7d441291fd9c4dc37320d411f94fb362523d47d37ab35c20b3ac9d4cd75cb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="16:7f:d1:29:5b:3b:b1:02:db:b3:72:92:c8:38:e7:cd" and 1476921600<=pe.signatures[i].not_after)
}
