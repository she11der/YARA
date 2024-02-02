rule SIGNATURE_BASE_Azrailphp_V1_0_Php
{
	meta:
		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "60152b96-e8d3-5b06-a855-fb64a490742b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4092-L4104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "26b2d3943395682e36da06ed493a3715"
		logic_hash = "4385f294e59b644fe86d8380db4f7926924eb744ad80735b78ef778d2f7e8ae0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "azrailphp"
		$s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
		$s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"

	condition:
		2 of them
}