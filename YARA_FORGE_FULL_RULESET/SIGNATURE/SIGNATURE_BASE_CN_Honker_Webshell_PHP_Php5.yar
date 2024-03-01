rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php5 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "ee063c4c-af06-520f-acfe-fba758b84d3c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L8-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0fd91b6ad400a857a6a65c8132c39e6a16712f19"
		logic_hash = "e882f115a67fe31ece1a81e1a2770b46370a92ac3aa23e348a12cdb5735e8a0e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii
		$s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii

	condition:
		uint16(0)==0x3f3c and filesize <300KB and all of them
}
