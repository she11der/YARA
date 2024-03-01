import "pe"

rule REVERSINGLABS_Cert_Blocklist_6F18946E5B773B7E32D9E7B4Fb8D434C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "53205508-568c-5356-9717-2915c8f3806c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16980-L16996"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fa285c17b43d1acdb05888074ecb16047209ade8f7f6191274f58eca7438dadf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VECTOR LLC (VEKTOR, OOO)" and pe.signatures[i].serial=="6f:18:94:6e:5b:77:3b:7e:32:d9:e7:b4:fb:8d:43:4c" and 1454716800<=pe.signatures[i].not_after)
}
