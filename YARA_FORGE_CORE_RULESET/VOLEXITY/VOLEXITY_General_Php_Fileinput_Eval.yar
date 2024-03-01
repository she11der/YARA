rule VOLEXITY_General_Php_Fileinput_Eval : Webshells General
{
	meta:
		description = "Look for PHP files which use file_get_contents and then shortly afterwards use an eval statement."
		author = "threatintel@volexity.com"
		id = "c00d8fee-f667-5979-ad2a-dbb762544c2f"
		date = "2021-06-16"
		modified = "2022-07-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L136-L152"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "c61f0ee13007e398f45711354a1ca948f7f34893c9bcbdf845be932b63bd746d"
		score = 75
		quality = 80
		tags = ""
		hash1 = "1a34c43611ee310c16acc383c10a7b8b41578c19ee85716b14ac5adbf0a13bd5"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$s1 = "file_get_contents(\"php://input\");"
		$s2 = "eval("

	condition:
		$s2 in (@s1[1]..@s1[1]+512)
}
