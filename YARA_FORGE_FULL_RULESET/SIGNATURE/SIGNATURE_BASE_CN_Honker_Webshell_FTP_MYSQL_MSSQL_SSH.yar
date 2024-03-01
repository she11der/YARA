rule SIGNATURE_BASE_CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "dd619901-6f0e-527e-9926-808176641c09"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1011-L1029"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fe63b215473584564ef2e08651c77f764999e8ac"
		logic_hash = "a66884c71ce0cce05ba6607bf66dc55bfae5393746328c06f5c9ca98005d0caf"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii
		$s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
		$s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii
		$s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii
		$s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii

	condition:
		filesize <20KB and 3 of them
}
