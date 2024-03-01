rule SIGNATURE_BASE_Pws_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file pws.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "1ec47c33-dbec-50bd-b4b0-8f00b704a816"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4523-L4535"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"
		logic_hash = "98dae8aab5bfd58f4264e318f5a5b5900b38687386f9d7f09c31da0f51d57bc0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
		$s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
		$s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"

	condition:
		2 of them
}
