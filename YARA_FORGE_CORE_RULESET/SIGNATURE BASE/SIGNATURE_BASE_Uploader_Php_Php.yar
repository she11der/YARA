rule SIGNATURE_BASE_Uploader_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file uploader.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "62aa783b-f12f-5bb5-9d96-7aee1666788b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3922-L3934"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0b53b67bb3b004a8681e1458dd1895d0"
		logic_hash = "6e6ffc4cad2a956cb2b6667928bac5996cf95cd36f43ba789144c46726471f07"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
		$s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
		$s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword

	condition:
		2 of them
}
