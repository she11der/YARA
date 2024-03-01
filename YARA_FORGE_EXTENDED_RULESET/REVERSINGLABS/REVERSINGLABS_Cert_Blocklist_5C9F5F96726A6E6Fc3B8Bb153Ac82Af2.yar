import "pe"

rule REVERSINGLABS_Cert_Blocklist_5C9F5F96726A6E6Fc3B8Bb153Ac82Af2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7619c39-33a0-5f99-b911-9d8a61a4683d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12370-L12386"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a61bcc4a90a75a429366e3f93929005b67325eccc6cad3df6b7a0c3692597828"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "1105 SOFTWARE LLC" and pe.signatures[i].serial=="5c:9f:5f:96:72:6a:6e:6f:c3:b8:bb:15:3a:c8:2a:f2" and 1679061408<=pe.signatures[i].not_after)
}
