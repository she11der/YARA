import "pe"

rule REVERSINGLABS_Cert_Blocklist_D875B3E3F2Db6C3Eb426E24946066111 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4aedeb77-181b-5422-bec4-93c84412bae4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8110-L8128"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9e181271d46c828b9ec266331e077b3b4891a193c71173447da383fad91ae878"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kubit LLC" and (pe.signatures[i].serial=="00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11" or pe.signatures[i].serial=="d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11") and 1606953600<=pe.signatures[i].not_after)
}
