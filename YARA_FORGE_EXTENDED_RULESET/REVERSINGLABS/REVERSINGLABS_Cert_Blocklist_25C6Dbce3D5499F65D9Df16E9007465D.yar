import "pe"

rule REVERSINGLABS_Cert_Blocklist_25C6Dbce3D5499F65D9Df16E9007465D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f6d0808d-4748-5b9f-9be2-7753292a6209"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12312-L12328"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "978f05f86734c63afe1e5929a58f3cfff75ef749ffda07252db90b6fe12508ec"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="25:c6:db:ce:3d:54:99:f6:5d:9d:f1:6e:90:07:46:5d" and 1626566400<=pe.signatures[i].not_after)
}
