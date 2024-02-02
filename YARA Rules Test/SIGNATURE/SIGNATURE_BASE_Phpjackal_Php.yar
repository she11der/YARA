rule SIGNATURE_BASE_Phpjackal_Php
{
	meta:
		description = "Semi-Auto-generated  - file phpjackal.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ae46cb97-1ff8-50ba-856f-c38fbb1e5163"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4704-L4715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ab230817bcc99acb9bdc0ec6d264d76f"
		logic_hash = "6e2ff262aecd08e5feaa274a7fd128d75565d6cc03341da7cbeb2949070705e5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s3 = "$dl=$_REQUEST['downloaD'];"
		$s4 = "else shelL(\"perl.exe $name $port\");"

	condition:
		1 of them
}