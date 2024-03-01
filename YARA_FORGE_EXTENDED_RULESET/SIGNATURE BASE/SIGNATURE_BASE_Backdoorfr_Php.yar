rule SIGNATURE_BASE_Backdoorfr_Php
{
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "5ba2b617-a873-5e80-9cfc-c61cc8d605f3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4849-L4860"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"
		logic_hash = "40a6fb41a65fd35acb7cdc36fdda90f5dc54b641adc3ba9eaae29c5e46622206"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
		$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"

	condition:
		1 of them
}
