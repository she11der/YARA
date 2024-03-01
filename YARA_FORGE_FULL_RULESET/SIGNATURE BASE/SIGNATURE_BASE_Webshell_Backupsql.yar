rule SIGNATURE_BASE_Webshell_Backupsql
{
	meta:
		description = "PHP Webshells Github Archive - file backupsql.php"
		author = "Florian Roth (Nextron Systems)"
		id = "15d6e967-1e53-53b4-a2cf-7786452495d4"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6235-L6250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "863e017545ec8e16a0df5f420f2d708631020dd4"
		logic_hash = "0126bfad6eb3861e8322ac3e11b4fd95bc8b88597d916e66c6646d7d5529c1d5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
		$s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
		$s2 = "* as email attachment, or send to a remote ftp server by" fullword
		$s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
		$s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "

	condition:
		2 of them
}
