rule ELCEEF_Obfuscated_IP_Address_In_URL
{
	meta:
		description = "Detects hexadecimal and octal IP address representations in URL"
		author = "marcin@ulikowski.pl"
		id = "76a4a876-25af-54f5-a01c-3dc9642ebad8"
		date = "2020-09-17"
		modified = "2022-12-12"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/evasive-urls-in-spam/"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Obfuscated_IPAddr_URL.yara#L1-L17"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "e31ceec11a6f87fbce67da8d1624ebec3b335950483df5a3e053b2549a36ea74"
		score = 75
		quality = 65
		tags = ""

	strings:
		$ = /="?http:\/\/0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.?\// nocase ascii wide
		$ = /="?http:\/\/0x[0-9a-f]{8}\.?\// nocase ascii wide
		$ = /="?http:\/\/0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.?\// nocase ascii wide
		$ = /="?http:\/\/[0-9]{8-10}\.?\// nocase ascii wide

	condition:
		any of them
}
