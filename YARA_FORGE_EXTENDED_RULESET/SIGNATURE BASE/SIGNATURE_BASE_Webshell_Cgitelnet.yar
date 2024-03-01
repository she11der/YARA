rule SIGNATURE_BASE_Webshell_Cgitelnet
{
	meta:
		description = "PHP Webshells Github Archive - file cgitelnet.php"
		author = "Florian Roth (Nextron Systems)"
		id = "b02d8549-ebfe-522c-9a6d-8657273da3ed"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6056-L6070"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"
		logic_hash = "e9b7096d5a19c9d5423bbfe125ae0347853919ab092efa98f0687a5d0cf68953"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "# Author Homepage: http://www.rohitab.com/" fullword
		$s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
		$s18 = "# in a command line on Windows NT." fullword
		$s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword

	condition:
		2 of them
}
