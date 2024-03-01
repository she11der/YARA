rule SIGNATURE_BASE_M_Hunting_Python_Backdoor_Commandparser_1 : FILE
{
	meta:
		description = "Finds strings indicative of the vmsyslog.py python backdoor."
		author = "Mandiant"
		id = "15cbca01-24e6-5538-bcfd-c3222337aaf5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_unc3886_virtualpita.yar#L57-L73"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "61ab3f6401d60ec36cd3ac980a8deb75"
		logic_hash = "eefc255079e914ac81d53baf4ae159052bfda4c670e8300306c0899b3ad00a48"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$key1 = "self.conn.readInt8()" ascii
		$key2 = "upload" ascii
		$key3 = "download" ascii
		$key4 = "shell" ascii
		$key5 = "execute" ascii
		$re1 = /def\srun.{,20}command\s?=\s?self\.conn\.readInt8\(\).{,75}upload.{,75}download.{,75}shell.{,75}execute/s

	condition:
		filesize <200KB and all of them
}
