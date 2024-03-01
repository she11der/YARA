import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2E4A279Bde2Eb688E8Ab30F5904Fa875 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3fd40418-9efe-5dfe-a4e2-01ff9c46a4d5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6229-L6240"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "768b2cb64f7ce359285721bbfd2f2f6aac4065ec234dc091933d962a7f0ab79a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0cdf4e992af760e59f3ea2f1648804d2a2b47bbc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lespeed Technology Co., Ltd" and pe.signatures[i].serial=="2e:4a:27:9b:de:2e:b6:88:e8:ab:30:f5:90:4f:a8:75")
}
