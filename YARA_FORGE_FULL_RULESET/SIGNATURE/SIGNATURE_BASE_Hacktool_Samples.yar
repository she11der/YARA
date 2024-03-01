import "pe"

rule SIGNATURE_BASE_Hacktool_Samples
{
	meta:
		description = "Hacktool"
		author = "Florian Roth"
		id = "ecacf84a-f66c-5c21-ae4b-fd9bfb5be384"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L88-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0064950d88eccbe670cd1dc70861d093c7f49f8f10e984aef4cfb4bcc94e4645"
		score = 50
		quality = 83
		tags = ""

	strings:
		$a = "Unable to uninstall the fgexec service"
		$b = "Unable to set socket to sniff"
		$c = "Failed to load SAM functions"
		$d = "Dump system passwords"
		$e = "Error opening sam hive or not valid file"
		$f = "Couldn't find LSASS pid"
		$g = "samdump.dll"
		$h = "WPEPRO SEND PACKET"
		$i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
		$j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
		$k = "arpspoof\\Debug"
		$l = "Success: The log has been cleared"
		$m = "clearlogs [\\\\computername"
		$n = "DumpUsers 1."
		$o = "dictionary attack with specified dictionary file"
		$p = "by Objectif Securite"
		$q = "objectif-securite"
		$r = "Cannot query LSA Secret on remote host"
		$s = "Cannot write to process memory on remote host"
		$t = "Cannot start PWDumpX service on host"
		$u = "usage: %s <system hive> <security hive>"
		$v = "username:domainname:LMhash:NThash"
		$w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
		$x = "Impersonation Tokens Available"
		$y = "failed to parse pwdump format string"
		$z = "Dumping password"

	condition:
		1 of them
}
