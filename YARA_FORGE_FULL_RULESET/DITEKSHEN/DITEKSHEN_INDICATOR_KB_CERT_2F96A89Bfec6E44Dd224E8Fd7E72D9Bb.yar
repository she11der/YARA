import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2F96A89Bfec6E44Dd224E8Fd7E72D9Bb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a905ee22-94c6-5d16-a9a4-a1c1528e4ac2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8086-L8099"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "94a5721bd3089f46699a947afcd03287712f94754666809e6495b01fc9cd6dcf"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f13e4801e13898e839183e3305e1dda7f4c0ebf6eaf7553e18c1ddd4edc94470"
		reason = "Gozi"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and pe.signatures[i].serial=="2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb")
}
