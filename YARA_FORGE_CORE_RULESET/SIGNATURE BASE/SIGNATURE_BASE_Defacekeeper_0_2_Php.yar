rule SIGNATURE_BASE_Defacekeeper_0_2_Php
{
	meta:
		description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "671323e2-42cb-5ce0-9839-5d01c446471c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4317-L4329"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "713c54c3da3031bc614a8a55dccd7e7f"
		logic_hash = "0ee3fed3441e9561867508e324d7a6b1808a8923513bf1c9b82f8238224c994c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
		$s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
		$s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"

	condition:
		1 of them
}
