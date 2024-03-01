import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A392F03Ded5D73Cdeeda75052A57176 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c0a8cc1c-7427-589b-9e32-8679e9cdf251"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8551-L8564"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ea0159ec1c4670c1e961a87131998fa796cf205eaa8a06bf829c61c9694fa5ef"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cf1d95b39cc695e90dc2ca8b1b50f33b71f9f21091df2b72ed97f0759b5ddde4"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLOWER COMPUTERS LTD" and pe.signatures[i].serial=="0a:39:2f:03:de:d5:d7:3c:de:ed:a7:50:52:a5:71:76")
}
